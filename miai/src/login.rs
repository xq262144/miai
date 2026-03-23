//! 登录小爱服务。

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64ct::{Base64, Encoding};
use cookie_store::{CookieStore, RawCookie};
use md5::{Digest, Md5};
use reqwest::{
    Client, RequestBuilder, Response, Url,
    header::{CONTENT_TYPE, SET_COOKIE},
};
use reqwest_cookie_store::CookieStoreMutex;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use sha1::Sha1;
use tracing::trace;

use crate::util::random_id;

/// 登录小爱服务。
///
/// 更低层级的抽象，可以用来辅助理解小爱服务的登录流程，或对登录进行更精细的控制。使用时需严格遵守先
/// [`login`][Login::login]，再 [`auth`][Login::auth]，最后 [`get_token`][Login::get_token] 的步骤。
#[derive(Clone, Debug)]
pub struct Login {
    client: Client,
    server: Url,
    username: String,
    password_hash: String,
    cookie_store: Arc<CookieStoreMutex>,
}

/// 登录时需要输入图片验证码。
#[derive(Clone, Debug)]
pub struct CaptchaChallenge {
    /// 原始验证码地址。
    pub url: String,
    /// 验证码图片字节。
    pub image: Vec<u8>,
    /// 响应体的 Content-Type。
    pub content_type: Option<String>,
    ick: String,
}

/// 登录时需要额外的二次验证。
#[derive(Clone, Debug)]
pub struct VerificationChallenge {
    /// 小米返回的验证地址。
    pub url: String,
}

/// 二维码登录挑战。
#[derive(Clone, Debug)]
pub struct QrLoginChallenge {
    /// 终端应当渲染的扫码链接。
    pub login_url: String,
    /// 小米返回的二维码图片地址。
    pub qr_url: String,
    poll_url: Url,
}

/// 初步登录的结果。
#[derive(Clone, Debug)]
pub enum LoginStep {
    /// 还需要走 `serviceLoginAuth2` 认证。
    NeedAuth(LoginResponse),
    /// 已经拿到了后续 `get_token` 所需的字段。
    Authenticated(AuthResponse),
}

const LOGIN_SERVER: &str = "https://account.xiaomi.com/pass/";
const ACCOUNT_SERVER: &str = "https://account.xiaomi.com/";
const LOGIN_UA: &str = "APP/com.xiaomi.mihome APPV/6.0.103 iosPassportSDK/3.9.0 iOS/14.4 miHSTS";

impl Login {
    pub fn new(username: impl Into<String>, password: impl AsRef<[u8]>) -> crate::Result<Self> {
        Self::with_password_hash(username.into(), hash_password(password))
    }

    /// 构造一个仅用于二维码登录的实例。
    pub fn new_qr() -> crate::Result<Self> {
        Self::with_password_hash(String::new(), String::new())
    }

    fn with_password_hash(username: String, password_hash: String) -> crate::Result<Self> {
        let server = Url::parse(LOGIN_SERVER)?;

        // 预先添加 Cookies
        let mut cookie_store = CookieStore::new(None);
        let device_id = random_device_id();
        for (name, value) in [("sdkVersion", "3.9"), ("deviceId", &device_id)] {
            let cookie = RawCookie::build((name, value)).path("/").build();
            cookie_store.insert_raw(&cookie, &server)?;
            trace!("预先添加 Cookies: {}", cookie);
        }
        let cookie_store = Arc::new(CookieStoreMutex::new(cookie_store));

        // 用于登录的 Client
        let client = Client::builder()
            .cookie_provider(Arc::clone(&cookie_store))
            .http1_only()
            .user_agent(LOGIN_UA)
            .build()?;

        Ok(Self {
            client,
            server,
            username,
            password_hash,
            cookie_store,
        })
    }

    /// 初步登录小爱服务。
    ///
    /// 结果中可能会出现登录失败的信息，但这无伤大雅，初步登录只是为了获取一些接下来认证所需的数据。
    pub async fn login(&self) -> crate::Result<LoginResponse> {
        match self.begin().await? {
            LoginStep::NeedAuth(response) => Ok(response),
            LoginStep::Authenticated(_) => Err(crate::Error::Login(
                "当前登录步骤已经完成认证，请直接继续获取 token".to_owned(),
            )),
        }
    }

    /// 初步登录，并自动识别是否已经完成认证。
    pub async fn begin(&self) -> crate::Result<LoginStep> {
        let raw = self.raw_login().await?;

        parse_login_step(raw)
    }

    /// 同 [`Login::login`]，但返回原始的 JSON。
    pub async fn raw_login(&self) -> crate::Result<Value> {
        // 初步登录以获取一些认证信息
        let url = self.server.join("serviceLogin?sid=micoapi&_json=true")?;
        let response = self
            .send_with_retry("初步登录请求", || self.client.get(url.clone()))
            .await?
            .error_for_status()?;
        self.trace_response_cookies("初步登录响应", &response);
        self.trace_cookie_state("初步登录响应后")?;
        let bytes = response.bytes().await?;
        // 前 11 个字节不知道是什么，后面追加 json 响应体
        let response = serde_json::from_slice(&bytes[11..])?;
        trace!("尝试初步登录: {response}");

        Ok(response)
    }

    /// 认证小爱服务。
    ///
    /// 需要使用初步登录的结果进行。
    pub async fn auth(&self, login_response: LoginResponse) -> crate::Result<AuthResponse> {
        let raw = self.raw_auth(login_response).await?;

        self.parse_auth_response(raw).await
    }

    /// 同 [`Login::auth`]，但返回原始的 JSON。
    pub async fn raw_auth(&self, login_response: LoginResponse) -> crate::Result<Value> {
        self.auth_request(login_response, None).await
    }

    /// 使用图片验证码重试认证。
    pub async fn auth_with_captcha(
        &self,
        login_response: LoginResponse,
        challenge: &CaptchaChallenge,
        captcha: &str,
    ) -> crate::Result<AuthResponse> {
        let raw = self
            .raw_auth_with_captcha(login_response, challenge, captcha)
            .await?;

        self.parse_auth_response(raw).await
    }

    /// 同 [`Login::auth_with_captcha`]，但返回原始的 JSON。
    pub async fn raw_auth_with_captcha(
        &self,
        login_response: LoginResponse,
        challenge: &CaptchaChallenge,
        captcha: &str,
    ) -> crate::Result<Value> {
        self.auth_request(login_response, Some((challenge, captcha)))
            .await
    }

    /// 提交二次验证收到的验证码。
    pub async fn submit_verification(
        &self,
        challenge: &VerificationChallenge,
        ticket: &str,
    ) -> crate::Result<()> {
        let methods = self.fetch_verification_methods(&challenge.url).await?;
        let mut last_error = None;

        for flag in methods {
            let Some(api) = verification_api(flag) else {
                continue;
            };
            let dc = now_millis().to_string();
            let url = self.account_url(api)?;
            let form = [
                ("_flag", flag.to_string()),
                ("ticket", ticket.to_owned()),
                ("trust", "true".to_owned()),
                ("_json", "true".to_owned()),
            ];
            let response = self
                .send_with_retry("提交二次验证请求", || {
                    self.client
                        .post(url.clone())
                        .query(&[("_dc", dc.clone())])
                        .form(&form)
                })
                .await?
                .error_for_status()?;
            self.trace_response_cookies("提交二次验证响应", &response);
            self.trace_cookie_state("提交二次验证响应后")?;
            let bytes = response.bytes().await?;
            let response = decode_json_bytes(&bytes)?;
            trace!("提交二次验证: {response}");

            if response.get("code").and_then(Value::as_i64) == Some(0) {
                if let Some(location) = response
                    .get("location")
                    .and_then(Value::as_str)
                    .filter(|location| !location.is_empty())
                {
                    let url = self.account_url(location)?;
                    let relay_response = self
                        .send_with_retry("二次验证跳转请求", || {
                            self.client.get(url.clone())
                        })
                        .await?;
                    self.trace_response_cookies("二次验证跳转响应", &relay_response);
                    trace!(
                        "二次验证跳转完成: status={}, url={}",
                        relay_response.status(),
                        relay_response.url()
                    );
                    self.trace_cookie_state("二次验证跳转后")?;
                }
                return Ok(());
            }

            last_error = Some(response);
        }

        if let Some(error) = last_error {
            Err(crate::Error::Login(format!(
                "二次验证失败: {}",
                login_error_message(&error)
            )))
        } else {
            Err(crate::Error::Login(
                "当前账号的二次验证方式不受支持".to_owned(),
            ))
        }
    }

    /// 获取小爱服务的 token，是登录的核心步骤。
    ///
    /// 需要在认证成功后进行。
    pub async fn get_token(&self, auth_response: AuthResponse) -> crate::Result<Value> {
        // 获取 serviceToken，存于 Cookies
        let client_sign = client_sign(&auth_response);
        let url = Url::parse_with_params(&auth_response.location, [("clientSign", &client_sign)])?;
        self.trace_cookie_state("获取 serviceToken 前")?;
        let response = self
            .send_with_retry("获取 serviceToken 请求", || {
                self.client.get(url.clone())
            })
            .await?
            .error_for_status()?;
        self.trace_response_cookies("获取 serviceToken 响应", &response);
        self.trace_cookie_state("获取 serviceToken 响应后")?;
        let response = response.json().await?;
        trace!("尝试获取 serviceToken: {response}");

        Ok(response)
    }

    /// 获取二维码登录挑战。
    pub async fn qr_challenge(&self) -> crate::Result<QrLoginChallenge> {
        let response = self.raw_login().await?;
        let location = response
            .get("location")
            .and_then(Value::as_str)
            .filter(|location| !location.is_empty())
            .ok_or_else(|| crate::Error::Login(login_error_message(&response)))?;
        let mut query = self
            .account_url(location)?
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        query.extend([
            ("theme".to_owned(), String::new()),
            ("bizDeviceType".to_owned(), String::new()),
            ("_hasLogo".to_owned(), "false".to_owned()),
            ("_qrsize".to_owned(), "240".to_owned()),
            ("_dc".to_owned(), now_millis().to_string()),
        ]);
        let url = Url::parse_with_params("https://account.xiaomi.com/longPolling/loginUrl", &query)?;
        let response = self
            .send_with_retry("获取扫码登录二维码请求", || self.client.get(url.clone()))
            .await?
            .error_for_status()?;
        self.trace_response_cookies("获取扫码登录二维码响应", &response);
        self.trace_cookie_state("获取扫码登录二维码响应后")?;
        let bytes = response.bytes().await?;
        let response = decode_json_bytes(&bytes)?;
        trace!("获取到扫码登录二维码: {response}");

        Ok(QrLoginChallenge {
            login_url: response
                .get("loginUrl")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| crate::Error::Login("扫码登录响应缺少 `loginUrl`".to_owned()))?
                .to_owned(),
            qr_url: response
                .get("qr")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| crate::Error::Login("扫码登录响应缺少 `qr`".to_owned()))?
                .to_owned(),
            poll_url: Url::parse(
                response
                    .get("lp")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| crate::Error::Login("扫码登录响应缺少 `lp`".to_owned()))?,
            )?,
        })
    }

    /// 等待用户扫码并完成登录。
    pub async fn wait_for_qr_scan(&self, challenge: &QrLoginChallenge) -> crate::Result<()> {
        let response = self
            .send_with_retry("扫码登录轮询请求", || {
                self.client.get(challenge.poll_url.clone())
            })
            .await?
            .error_for_status()?;
        self.trace_response_cookies("扫码登录轮询响应", &response);
        self.trace_cookie_state("扫码登录轮询响应后")?;
        let bytes = response.bytes().await?;
        let response = decode_json_bytes(&bytes)?;
        trace!("扫码登录轮询结果: {response}");

        if has_auth_fields(&response) {
            self.get_token(serde_json::from_value(response)?).await?;
            return Ok(());
        }

        let location = response
            .get("location")
            .and_then(Value::as_str)
            .filter(|location| !location.is_empty())
            .ok_or_else(|| crate::Error::Login(login_error_message(&response)))?;
        let url = self.account_url(location)?;
        let response = self
            .send_with_retry("扫码登录回调请求", || self.client.get(url.clone()))
            .await?;
        self.trace_response_cookies("扫码登录回调响应", &response);
        trace!(
            "扫码登录回调完成: status={}, url={}",
            response.status(),
            response.url()
        );
        self.trace_cookie_state("扫码登录回调后")?;

        if self.has_cookie("serviceToken") {
            return Ok(());
        }

        let bytes = response.bytes().await?;
        if looks_like_json_bytes(&bytes) {
            let response = decode_json_bytes(&bytes)?;
            trace!("扫码登录回调响应体: {response}");
            if has_auth_fields(&response) {
                self.get_token(serde_json::from_value(response)?).await?;
                return Ok(());
            }
        }

        if self.has_cookie("serviceToken") {
            Ok(())
        } else {
            Err(crate::Error::Login(
                "扫码登录成功，但未获取到 `serviceToken`".to_owned(),
            ))
        }
    }

    /// 消耗 `Login` 并提取 Cookies，其中存储了当前的登录状态。
    pub fn into_cookie_store(self) -> Arc<CookieStoreMutex> {
        self.cookie_store
    }

    async fn auth_request(
        &self,
        login_response: LoginResponse,
        captcha: Option<(&CaptchaChallenge, &str)>,
    ) -> crate::Result<Value> {
        let url = self.server.join("serviceLoginAuth2")?;
        let mut form = vec![
            ("_json".to_owned(), "true".to_owned()),
            ("qs".to_owned(), login_response.qs),
            ("sid".to_owned(), login_response.sid),
            ("_sign".to_owned(), login_response._sign),
            ("callback".to_owned(), login_response.callback),
            ("user".to_owned(), self.username.clone()),
            ("hash".to_owned(), self.password_hash.clone()),
        ];

        if let Some((challenge, captcha_code)) = captcha {
            self.insert_cookie("ick", &challenge.ick)?;
            form.push(("captCode".to_owned(), captcha_code.to_owned()));
        }
        let dc = captcha.map(|_| now_millis().to_string());
        let response = self
            .send_with_retry("认证请求", || {
                let request = self.client.post(url.clone());
                let request = if let Some(dc) = &dc {
                    request.query(&[("_dc", dc.clone())])
                } else {
                    request
                };
                request.form(&form)
            })
            .await?
            .error_for_status()?;
        self.trace_response_cookies("认证响应", &response);
        self.trace_cookie_state("认证响应后")?;
        let bytes = response.bytes().await?;
        let response = decode_json_bytes(&bytes)?;
        trace!("尝试认证: {response}");

        Ok(response)
    }

    async fn parse_auth_response(&self, response: Value) -> crate::Result<AuthResponse> {
        if has_auth_fields(&response) {
            return Ok(serde_json::from_value(response)?);
        }

        if let Some(url) = response.get("notificationUrl").and_then(Value::as_str) {
            if !url.is_empty() {
                return Err(crate::Error::NeedVerification(VerificationChallenge {
                    url: self.account_url(url)?.into(),
                }));
            }
        }

        if let Some(url) = response.get("captchaUrl").and_then(Value::as_str) {
            if !url.is_empty() {
                let challenge = self.fetch_captcha(url).await?;
                return Err(crate::Error::NeedCaptcha(challenge));
            }
        }

        Err(crate::Error::Login(login_error_message(&response)))
    }

    async fn fetch_captcha(&self, url: &str) -> crate::Result<CaptchaChallenge> {
        let url = self.account_url(url)?;
        let response = self
            .send_with_retry("获取验证码请求", || self.client.get(url.clone()))
            .await?
            .error_for_status()?;
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let ick = response
            .cookies()
            .find(|cookie| cookie.name() == "ick")
            .map(|cookie| cookie.value().to_owned())
            .ok_or_else(|| crate::Error::Login("验证码响应缺少 `ick`".to_owned()))?;
        let image = response.bytes().await?.to_vec();

        Ok(CaptchaChallenge {
            url: url.into(),
            image,
            content_type,
            ick,
        })
    }

    async fn fetch_verification_methods(&self, url: &str) -> crate::Result<Vec<i64>> {
        let list_url = verification_list_url(url)
            .ok_or_else(|| crate::Error::Login(format!("无法识别的二次验证地址: {url}")))?;
        let url = self.account_url(&list_url)?;
        let bytes = self
            .send_with_retry("获取二次验证方式请求", || {
                self.client.get(url.clone())
            })
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let response = decode_json_bytes(&bytes)?;
        trace!("获取到二次验证方式: {response}");

        let mut methods = response
            .get("options")
            .and_then(Value::as_array)
            .map(|options| options.iter().filter_map(Value::as_i64).collect::<Vec<_>>())
            .unwrap_or_default();
        if methods.is_empty() {
            if let Some(flag) = response.get("flag").and_then(Value::as_i64) {
                methods.push(flag);
            }
        }

        Ok(methods)
    }

    fn account_url(&self, url: &str) -> crate::Result<Url> {
        if url.starts_with("http://") || url.starts_with("https://") {
            Ok(Url::parse(url)?)
        } else {
            Ok(Url::parse(ACCOUNT_SERVER)?.join(url.trim_start_matches('/'))?)
        }
    }

    fn insert_cookie(&self, name: &str, value: &str) -> crate::Result<()> {
        let cookie = RawCookie::build((name, value)).path("/").build();
        self.cookie_store
            .lock()
            .unwrap()
            .insert_raw(&cookie, &self.server)?;
        trace!("手动写入 Cookie: {}", cookie);

        Ok(())
    }

    fn has_cookie(&self, name: &str) -> bool {
        self.cookie_store
            .lock()
            .unwrap()
            .iter_any()
            .any(|cookie| cookie.name() == name)
    }

    fn trace_response_cookies(&self, label: &str, response: &Response) {
        let mut found = false;
        for value in response.headers().get_all(SET_COOKIE) {
            found = true;
            trace!(
                "{label} Set-Cookie: {}",
                value.to_str().unwrap_or("<non-utf8>")
            );
        }
        if !found {
            trace!("{label} Set-Cookie: <none>");
        }
    }

    fn trace_cookie_state(&self, label: &str) -> crate::Result<()> {
        let account_url = Url::parse("https://account.xiaomi.com/")?;
        let xiaomi_url = Url::parse("https://xiaomi.com/")?;
        let api_url = Url::parse("https://api2.mina.mi.com/")?;
        let store = self.cookie_store.lock().unwrap();
        let cookies = store
            .iter_any()
            .map(|cookie| {
                format!(
                    "{}={}; domain={}; path={}; secure={:?}; http_only={:?}; expires={:?}",
                    cookie.name(),
                    cookie.value(),
                    String::from(&cookie.domain),
                    String::from(&cookie.path),
                    cookie.secure(),
                    cookie.http_only(),
                    cookie.expires,
                )
            })
            .collect::<Vec<_>>();
        trace!(
            "{label} cookie jar: {}",
            if cookies.is_empty() {
                "<empty>".to_owned()
            } else {
                cookies.join(" | ")
            }
        );
        trace!(
            "{label} -> account.xiaomi.com request cookies: {}",
            join_request_cookies(&store, &account_url)
        );
        trace!(
            "{label} -> xiaomi.com request cookies: {}",
            join_request_cookies(&store, &xiaomi_url)
        );
        trace!(
            "{label} -> api2.mina.mi.com request cookies: {}",
            join_request_cookies(&store, &api_url)
        );

        Ok(())
    }

    async fn send_with_retry<F>(&self, label: &str, mut build: F) -> crate::Result<Response>
    where
        F: FnMut() -> RequestBuilder,
    {
        const ATTEMPTS: usize = 3;

        for attempt in 1..=ATTEMPTS {
            match build().send().await {
                Ok(response) => {
                    trace!("{label}: attempt={attempt} status={}", response.status());
                    return Ok(response);
                }
                Err(error) => {
                    trace!("{label}: attempt={attempt} error={error}");
                    if attempt == ATTEMPTS {
                        return Err(error.into());
                    }
                }
            }
        }

        unreachable!("retry loop must return")
    }
}

/// [`Login::login`] 的响应体，但仅包含 [`Login::auth`] 所需的字段。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub qs: String,
    pub sid: String,
    pub _sign: String,
    pub callback: String,
}

/// [`Login::auth`] 的响应体，但仅包含 [`Login::get_token`] 所需的字段。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub location: String,
    pub nonce: Number,
    pub ssecurity: String,
}

fn random_device_id() -> String {
    let mut device_id = random_id(16);
    device_id.make_ascii_uppercase();

    device_id
}

fn hash_password(password: impl AsRef<[u8]>) -> String {
    let result = Md5::new().chain_update(password).finalize();
    let mut result = base16ct::lower::encode_string(&result);
    result.make_ascii_uppercase();

    result
}

fn client_sign(payload: &AuthResponse) -> String {
    let nsec = Sha1::new()
        .chain_update("nonce=")
        .chain_update(payload.nonce.to_string())
        .chain_update("&")
        .chain_update(&payload.ssecurity)
        .finalize();

    Base64::encode_string(&nsec)
}

fn has_auth_fields(response: &Value) -> bool {
    response.get("nonce").is_some()
        && response.get("ssecurity").is_some()
        && response
            .get("location")
            .and_then(Value::as_str)
            .is_some_and(|location| !location.is_empty())
}

fn parse_login_step(response: Value) -> crate::Result<LoginStep> {
    if has_auth_fields(&response) {
        return Ok(LoginStep::Authenticated(serde_json::from_value(response)?));
    }

    match serde_json::from_value::<LoginResponse>(response.clone()) {
        Ok(response) => Ok(LoginStep::NeedAuth(response)),
        Err(_) => Err(crate::Error::Login(login_error_message(&response))),
    }
}

fn login_error_message(response: &Value) -> String {
    let mut parts = Vec::new();

    if let Some(code) = response.get("code").and_then(Value::as_i64) {
        parts.push(format!("code={code}"));
    }
    if let Some(result) = response.get("result").and_then(Value::as_str) {
        parts.push(format!("result={result}"));
    }
    if let Some(message) = response
        .get("description")
        .and_then(Value::as_str)
        .or_else(|| response.get("desc").and_then(Value::as_str))
    {
        parts.push(message.to_owned());
    }
    if let Some(url) = response.get("captchaUrl").and_then(Value::as_str) {
        if !url.is_empty() {
            parts.push(format!("captchaUrl={url}"));
        }
    }
    if let Some(url) = response.get("notificationUrl").and_then(Value::as_str) {
        if !url.is_empty() {
            parts.push(format!("notificationUrl={url}"));
        }
    }

    if parts.is_empty() {
        format!("返回了未识别的认证响应: {response}")
    } else {
        parts.join(", ")
    }
}

fn decode_json_bytes(bytes: &[u8]) -> crate::Result<Value> {
    let bytes = bytes.strip_prefix(b"&&&START&&&").unwrap_or(bytes);

    Ok(serde_json::from_slice(bytes)?)
}

fn looks_like_json_bytes(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_prefix(b"&&&START&&&").unwrap_or(bytes);

    matches!(bytes.first(), Some(b'{') | Some(b'['))
}

fn verification_api(flag: i64) -> Option<&'static str> {
    match flag {
        4 => Some("/identity/auth/verifyPhone"),
        8 => Some("/identity/auth/verifyEmail"),
        _ => None,
    }
}

fn verification_list_url(url: &str) -> Option<String> {
    const AUTH_START_PATH: &str = "fe/service/identity/authStart";

    url.contains(AUTH_START_PATH)
        .then(|| url.replacen(AUTH_START_PATH, "identity/list", 1))
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn join_request_cookies(store: &CookieStore, url: &Url) -> String {
    let cookies = store
        .get_request_values(url)
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>();

    if cookies.is_empty() {
        "<none>".to_owned()
    } else {
        cookies.join("; ")
    }
}
