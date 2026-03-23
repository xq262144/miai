use std::{
    collections::HashMap,
    io::{BufRead, Write},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64ct::{Base64, Encoding};
use cookie_store::{
    RawCookie,
    serde::json::{load_all, save_incl_expired_and_nonpersistent},
};
use hmac::{Hmac, Mac};
use reqwest::{
    Client, Url,
    header::{COOKIE, HeaderMap, HeaderValue},
};
use reqwest_cookie_store::CookieStoreMutex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use time::OffsetDateTime;
use tracing::trace;

use crate::{
    Error, XiaoaiResponse, conversation,
    login::{Login, LoginStep},
    util::random_id,
};

const API_SERVER: &str = "https://api2.mina.mi.com/";
const API_UA: &str = "MiHome/6.0.103 (com.xiaomi.mihome; build:6.0.103.1; iOS 14.4.0) Alamofire/6.0.103 MICO/iOSApp/appStore/6.0.103";
const ACCOUNT_SERVER: &str = "https://account.xiaomi.com/pass/";
const ACCOUNT_UA: &str = "APP/com.xiaomi.mihome APPV/6.0.103 iosPassportSDK/3.9.0 iOS/14.4 miHSTS";
const MIIO_SERVER: &str = "https://api.io.mi.com/app";
const MIIO_UA: &str = "iOS-14.4-6.0.103-iPhone12,3--D7744744F7AF32F0544445285880DD63E47D9BE9-8816080-84A3F44E137B71AE-iPhone";

/// 提供小爱服务请求。
///
/// `Xiaoai` 代表着一个账号的登录状态，但如果需要重用的话，也无需再包一层
/// [`std::rc::Rc`] 或 [`Arc`]，`Xiaoai` 已经在内部使用 [`Arc`] 共享状态。
#[derive(Clone, Debug)]
pub struct Xiaoai {
    client: Client,
    cookie_store: Arc<CookieStoreMutex>,
    miio_auth: Arc<std::sync::Mutex<Option<MiioAuth>>>,
    server: Url,
}

impl Xiaoai {
    /// 登录以调用小爱服务。
    pub async fn login(username: &str, password: &str) -> crate::Result<Self> {
        let login = Login::new(username, password)?;
        let auth_response = match login.begin().await? {
            LoginStep::NeedAuth(login_response) => login.auth(login_response).await?,
            LoginStep::Authenticated(auth_response) => auth_response,
        };
        login.get_token(auth_response).await?;

        Self::from_login(login)
    }

    /// 从 [`Login`][`crate::login::Login`] 构造。
    pub fn from_login(login: Login) -> crate::Result<Self> {
        let cookie_store = login.into_cookie_store();
        let client = Client::builder()
            .user_agent(API_UA)
            .cookie_provider(cookie_store.clone())
            .build()?;

        Ok(Self {
            client,
            cookie_store,
            miio_auth: Arc::new(std::sync::Mutex::new(None)),
            server: Url::parse(API_SERVER)?,
        })
    }

    /// 列出所有设备的信息。
    pub async fn device_info(&self) -> crate::Result<Vec<DeviceInfo>> {
        self.raw_device_info().await?.extract_data()
    }

    /// 同 [`Self::device_info`]，但返回原始的响应。
    pub async fn raw_device_info(&self) -> crate::Result<XiaoaiResponse> {
        let response = self.get("admin/v2/device_list?master=0").await?;
        trace!("获取到设备列表: {}", response.data);

        Ok(response)
    }

    /// 返回内部使用的 [`reqwest::Client`]。
    ///
    /// 该 `Client` 会共享登录状态，可以用来做一些 `Xiaoai` 没有提供的更底层的请求。
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// 小爱服务的通用 GET 请求。
    ///
    /// API 服务器会和 `uri` 做 [`Url::join`]。
    pub async fn get(&self, uri: &str) -> crate::Result<XiaoaiResponse> {
        let request_id = random_request_id();
        let url =
            Url::parse_with_params(self.server.join(uri)?.as_str(), [("requestId", request_id)])?;
        trace!("小爱 GET 请求: {url}");
        let response = self
            .client
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?
            .json::<XiaoaiResponse>()
            .await?;
        trace!(
            "小爱 GET 响应: url={url}, code={}, message={}, data={}",
            response.code, response.message, response.data
        );
        let response = response.error_for_code()?;

        Ok(response)
    }

    /// 小爱服务的通用 POST 请求。
    ///
    /// 同 [`Self::get`]，但可以带表单数据。
    pub async fn post(
        &self,
        uri: &str,
        mut form: HashMap<&str, &str>,
    ) -> crate::Result<XiaoaiResponse> {
        let request_id = random_request_id();
        form.insert("requestId", &request_id);
        let url = self.server.join(uri)?;
        trace!("小爱 POST 请求: url={url}, form={form:?}");
        let response = self
            .client
            .post(url.clone())
            .form(&form)
            .send()
            .await?
            .error_for_status()?
            .json::<XiaoaiResponse>()
            .await?;
        trace!(
            "小爱 POST 响应: url={url}, code={}, message={}, data={}",
            response.code, response.message, response.data
        );
        let response = response.error_for_code()?;

        Ok(response)
    }

    /// 保存登录状态到 `writer`。
    ///
    /// 状态被保存为明文的 json，请注意安全性。参见
    /// [`cookie_store::serde::json::save_incl_expired_and_nonpersistent`]。
    ///
    /// # Panics
    ///
    /// 当内部发生锁中毒时会 panic。
    pub fn save<W: Write>(&self, writer: &mut W) -> cookie_store::Result<()> {
        save_incl_expired_and_nonpersistent(&self.cookie_store.lock().unwrap(), writer)
    }

    /// 从 `reader` 加载登录状态。
    ///
    /// **不会**验证登录状态的有效性，如果在请求时出错，请尝试重新
    /// [`login`][Self::login]。另请参见 [`cookie_store::serde::json::load_all`]。
    pub fn load<R: BufRead>(reader: R) -> cookie_store::Result<Self> {
        let cookie_store = Arc::new(CookieStoreMutex::new(load_all(reader)?));
        let client = Client::builder()
            .user_agent(API_UA)
            .cookie_provider(Arc::clone(&cookie_store))
            .build()?;

        Ok(Self {
            client,
            cookie_store,
            miio_auth: Arc::new(std::sync::Mutex::new(None)),
            server: Url::parse(API_SERVER)?,
        })
    }

    /// 向小爱设备发送 OpenWrt UBUS 调用请求。
    pub async fn ubus_call(
        &self,
        device_id: &str,
        path: &str,
        method: &str,
        message: &str,
    ) -> crate::Result<XiaoaiResponse> {
        trace!("UBUS 调用: device_id={device_id}, path={path}, method={method}, message={message}");
        let form = HashMap::from([
            ("deviceId", device_id),
            ("method", method),
            ("path", path),
            ("message", message),
        ]);

        self.post("remote/ubus", form).await
    }

    /// 请求小爱设备播报文本。
    pub async fn tts(&self, device_id: &str, text: &str) -> crate::Result<XiaoaiResponse> {
        if let Some(info) = self.device_info_for_command(device_id).await? {
            if let Some(command) = miio_tts_command(&info.hardware) {
                trace!(
                    "设备 {device_id} 命中 MiIO TTS 兼容分支: hardware={}, miot_did={:?}, command={command}",
                    info.hardware, info.miot_did
                );
                match self.miio_action(&info, command, [json!(text)]).await {
                    Ok(response) => return Ok(response),
                    Err(error) => {
                        trace!("MiIO TTS 失败，回退到 ubus: {error}");
                    }
                }
            }
        }

        let message = json!({"text": text}).to_string();

        self.ubus_call(device_id, "mibrain", "text_to_speech", &message)
            .await
    }

    /// 请求小爱播放 `url`。
    pub async fn play_url(&self, device_id: &str, url: &str) -> crate::Result<XiaoaiResponse> {
        let message = json!({
            "url": url,
            // type 字段不仅能控制亮灯行为，还能控制暂停行为？
            // 比如在机型 L16A 上，设为 3 才能有完整的播放、暂停控制，但无法停止
            // 设为 0、1 可以播放、停止，但暂停后就无法恢复，设为 2 则无法暂停
            // 貌似每个机型都不太一样，参考 https://github.com/yihong0618/MiService/issues/30
            "type": 3,
            "media": "app_ios"
        })
        .to_string();

        self.ubus_call(device_id, "mediaplayer", "player_play_url", &message)
            .await
    }

    /// 请求小爱播放音乐。
    ///
    /// 和 [`Self::play_url`] 相比，此方法针对音频特化，能支持更多参数，但并非所有机型都支持。
    /// 目前尚不支持配置这些参数，仅用作播放音乐的另一种方案。
    pub async fn play_music(&self, device_id: &str, url: &str) -> crate::Result<XiaoaiResponse> {
        const AUDIO_ID: &str = "1582971365183456177";
        const ID: &str = "355454500";
        let message = json!({
            "startaudioid": AUDIO_ID,
            "music": {
                "payload": {
                    // 来自 miservice:
                    // If set to "MUSIC", the light will be on
                    // "audio_type": "MUSIC",
                    "audio_items": [
                        {
                            "item_id": {
                                "audio_id": AUDIO_ID,
                                "cp": {
                                    "album_id": "-1",
                                    "episode_index": 0,
                                    "id": ID,
                                    "name": "xiaowei",
                                },
                            },
                            "stream": {"url": url},
                        }
                    ],
                    "list_params": {
                        "listId": "-1",
                        "loadmore_offset": 0,
                        "origin": "xiaowei",
                        "type": "MUSIC",
                    },
                },
                "play_behavior": "REPLACE_ALL",
            }
        })
        .to_string();

        self.ubus_call(device_id, "mediaplayer", "player_play_music", &message)
            .await
    }

    /// 请求小爱调整音量。
    pub async fn set_volume(&self, device_id: &str, volume: u32) -> crate::Result<XiaoaiResponse> {
        let message = json!({
            "volume": volume,
            "media": "app_ios"
        })
        .to_string();

        self.ubus_call(device_id, "mediaplayer", "player_set_volume", &message)
            .await
    }

    /// 请求小爱执行文本。
    ///
    /// 效果和口头询问一样。
    pub async fn nlp(&self, device_id: &str, text: &str) -> crate::Result<XiaoaiResponse> {
        if let Some(info) = self.device_info_for_command(device_id).await? {
            if let Some(command) = miio_ask_command(&info.hardware) {
                trace!(
                    "设备 {device_id} 命中 MiIO 提问兼容分支: hardware={}, miot_did={:?}, command={command}",
                    info.hardware, info.miot_did
                );
                match self
                    .miio_action(&info, command, [json!(text), json!(1)])
                    .await
                {
                    Ok(response) => return Ok(response),
                    Err(error) => {
                        trace!("MiIO 提问失败，回退到 ubus: {error}");
                    }
                }
            }
        }

        let message = json!({
            "tts": 1,
            "nlp": 1,
            "nlp_text": text
        })
        .to_string();

        self.ubus_call(device_id, "mibrain", "ai_service", &message)
            .await
    }

    /// 获取播放器的状态信息。
    ///
    /// 可能包含播放状态，音量和循环播放设置。
    pub async fn player_status(&self, device_id: &str) -> crate::Result<XiaoaiResponse> {
        let message = json!({"media": "app_ios"}).to_string();

        self.ubus_call(device_id, "mediaplayer", "player_get_play_status", &message)
            .await
    }

    /// 设置播放器的播放状态。
    pub async fn set_play_state(
        &self,
        device_id: &str,
        state: PlayState,
    ) -> crate::Result<XiaoaiResponse> {
        let action = match state {
            PlayState::Play => "play",
            PlayState::Pause => "pause",
            PlayState::Stop => "stop",
            PlayState::Toggle => "toggle",
        };
        let message = json!({"action": action, "media": "app_ios"}).to_string();

        self.ubus_call(device_id, "mediaplayer", "player_play_operation", &message)
            .await
    }

    /// 获取小爱的对话记录。
    ///
    /// 会获取直到 `until` 前最多 `limit` 条记录，请注意 `device_id` 要和 `hardware` 相匹配。
    ///
    /// # Panics
    ///
    /// 当内部的 Cookies 发生锁中毒时会 panic。
    pub async fn conversations(
        &self,
        device_id: &str,
        hardware: &str,
        until: OffsetDateTime,
        limit: u32,
    ) -> crate::Result<conversation::Data> {
        // 这个响应体的 `data` 是 JSON 字符串，需要通过 String 中转一层
        let data_string: String = self
            .raw_conversations(device_id, hardware, until, limit)
            .await?
            .extract_data()?;
        let data = serde_json::from_str(&data_string)?;

        Ok(data)
    }

    /// 同 [`Self::conversations`]，但返回原始的响应。
    pub async fn raw_conversations(
        &self,
        device_id: &str,
        hardware: &str,
        until: OffsetDateTime,
        limit: u32,
    ) -> crate::Result<XiaoaiResponse> {
        let url = Url::parse_with_params(
            "https://userprofile.mina.mi.com/device_profile/v2/conversation?source=dialogu",
            &[
                ("hardware", hardware),
                ("timestamp", &(until.unix_timestamp() * 1000).to_string()),
                ("limit", &limit.to_string()),
            ],
        )?;

        // 服务端会从 Cookies 中读取 `deviceId`
        let cookie = RawCookie::build(("deviceId", device_id))
            .domain(url.domain().unwrap_or_default())
            .build();
        self.cookie_store
            .lock()
            .unwrap()
            .insert_raw(&cookie, &url)?;
        let response: XiaoaiResponse = self.client.get(url).send().await?.json().await?;
        trace!("获取到对话记录: {}", response.data);

        Ok(response)
    }

    async fn device_info_for_command(&self, device_id: &str) -> crate::Result<Option<DeviceInfo>> {
        Ok(self
            .device_info()
            .await?
            .into_iter()
            .find(|info| info.device_id == device_id))
    }

    async fn miio_action<I>(
        &self,
        info: &DeviceInfo,
        command: &str,
        args: I,
    ) -> crate::Result<XiaoaiResponse>
    where
        I: IntoIterator<Item = Value>,
    {
        let did = info
            .miot_did
            .as_deref()
            .ok_or_else(|| Error::Login(format!("设备 `{}` 缺少 `miotDID`", info.device_id)))?;
        let (siid, aiid) = parse_miio_action(command)?;
        let params = json!({
            "did": did,
            "siid": siid,
            "aiid": aiid,
            "in": args.into_iter().collect::<Vec<_>>(),
        });
        let response = self
            .miio_request("/miotspec/action", json!({ "params": params }))
            .await?;

        Ok(miio_response(response))
    }

    async fn miio_request(&self, uri: &str, payload: Value) -> crate::Result<Value> {
        match self.miio_request_once(uri, &payload).await {
            Ok(response) => Ok(response),
            Err(first_error) if is_auth_error(&first_error) => {
                trace!("MiIO 请求鉴权失败，重新登录 xiaomiio 后重试: {first_error}");
                self.clear_miio_auth();
                self.miio_request_once(uri, &payload).await
            }
            Err(first_error) => Err(first_error),
        }
    }

    async fn miio_request_once(&self, uri: &str, payload: &Value) -> crate::Result<Value> {
        let auth = self.miio_auth().await?;
        let data = serde_json::to_string(payload)?;
        let signed = sign_miio_data(uri, &data, &auth.ssecurity)?;
        let cookie = format!(
            "PassportDeviceId={}; userId={}; serviceToken={}",
            auth.device_id, auth.user_id, auth.service_token
        );
        let url = Url::parse(&format!("{MIIO_SERVER}{uri}"))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-xiaomi-protocal-flag-cli",
            HeaderValue::from_static("PROTOCAL-HTTP2"),
        );
        let cookie_header = HeaderValue::from_str(&cookie)
            .map_err(|error| Error::Login(format!("MiIO Cookie 无效: {error}")))?;
        headers.insert(COOKIE, cookie_header);
        trace!("MiIO 请求: url={url}, cookie={cookie:?}, payload={payload}, signed={signed:?}");
        let response = self
            .client
            .post(url.clone())
            .headers(headers)
            .header(reqwest::header::USER_AGENT, MIIO_UA)
            .form(&signed)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        trace!("MiIO 响应: status={status}, url={url}, body={body}");
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Login("MiIO 请求未授权".to_owned()));
        }
        if !status.is_success() {
            return Err(Error::Login(format!(
                "MiIO 请求失败: status={status}, body={body}"
            )));
        }

        Ok(serde_json::from_str(&body)?)
    }

    async fn miio_auth(&self) -> crate::Result<MiioAuth> {
        if let Some(auth) = self.miio_auth.lock().unwrap().clone() {
            return Ok(auth);
        }

        let auth = self.login_xiaomiio().await?;
        *self.miio_auth.lock().unwrap() = Some(auth.clone());

        Ok(auth)
    }

    fn clear_miio_auth(&self) {
        *self.miio_auth.lock().unwrap() = None;
    }

    async fn login_xiaomiio(&self) -> crate::Result<MiioAuth> {
        let client = Client::builder()
            .cookie_provider(self.cookie_store.clone())
            .http1_only()
            .user_agent(ACCOUNT_UA)
            .build()?;
        let url = Url::parse(ACCOUNT_SERVER)?.join("serviceLogin?sid=xiaomiio&_json=true")?;
        trace!("尝试获取 xiaomiio 登录态: {url}");
        let response = client.get(url.clone()).send().await?.error_for_status()?;
        let bytes = response.bytes().await?;
        let raw = decode_account_json(&bytes)?;
        trace!("xiaomiio 初步登录响应: {raw}");
        let auth = parse_service_auth_response(raw)?;
        let client_sign = account_client_sign(&auth.ssecurity, &auth.nonce);
        let location = Url::parse_with_params(&auth.location, [("clientSign", client_sign)])?;
        trace!("尝试获取 xiaomiio serviceToken: {location}");
        let response = client
            .get(location.clone())
            .send()
            .await?
            .error_for_status()?;
        let service_token = response
            .cookies()
            .find(|cookie| cookie.name() == "serviceToken")
            .map(|cookie| cookie.value().to_owned())
            .or_else(|| self.cookie_value("serviceToken"))
            .ok_or_else(|| Error::Login("xiaomiio 响应缺少 `serviceToken`".to_owned()))?;
        let user_id = self
            .cookie_value("userId")
            .ok_or_else(|| Error::Login("当前登录状态缺少 `userId`".to_owned()))?;
        let device_id = self
            .cookie_value("deviceId")
            .ok_or_else(|| Error::Login("当前登录状态缺少 `deviceId`".to_owned()))?;
        trace!(
            "获取到 xiaomiio 登录态: user_id={user_id}, device_id={device_id}, service_token_len={}",
            service_token.len()
        );

        Ok(MiioAuth {
            device_id,
            service_token,
            ssecurity: auth.ssecurity,
            user_id,
        })
    }

    fn cookie_value(&self, name: &str) -> Option<String> {
        self.cookie_store
            .lock()
            .unwrap()
            .iter_any()
            .find(|cookie| cookie.name() == name)
            .map(|cookie| cookie.value().to_owned())
    }
}

/// 表示播放器的播放状态。
#[derive(Clone, Debug)]
pub enum PlayState {
    Play,
    Pause,
    Stop,
    /// 在播放和暂停之间切换。
    Toggle,
}

/// 小爱设备信息。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    /// 设备 ID。
    ///
    /// 每个与设备相关的请求都会用 ID 指明对象。
    #[serde(rename = "deviceID")]
    pub device_id: String,

    /// 设备名称。
    pub name: String,

    /// 机型。
    pub hardware: String,

    /// MiIO / MIoT 设备 DID。
    #[serde(
        rename = "miotDID",
        default,
        deserialize_with = "deserialize_optional_string"
    )]
    pub miot_did: Option<String>,

    /// 设备在线状态。
    #[serde(default)]
    pub presence: Option<String>,
}

#[derive(Clone, Debug)]
struct MiioAuth {
    device_id: String,
    service_token: String,
    ssecurity: String,
    user_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ServiceAuthResponse {
    location: String,
    nonce: serde_json::Number,
    ssecurity: String,
}

#[derive(Clone, Debug, Serialize)]
struct MiioSignedPayload {
    _nonce: String,
    data: String,
    signature: String,
}

fn random_request_id() -> String {
    let mut request_id = random_id(30);
    request_id.insert_str(0, "app_ios_");

    request_id
}

fn miio_tts_command(hardware: &str) -> Option<&'static str> {
    match hardware {
        "OH2" | "ASX4B" | "L05B" | "L05C" => Some("5-3"),
        "OH2P" | "L15A" | "X10A" | "L17A" | "X6A" | "X08E" => Some("7-3"),
        "LX06" | "S12" | "LX5A" | "LX01" | "LX05" | "L06A" | "LX04" => Some("5-1"),
        "L09A" => Some("3-1"),
        _ => None,
    }
}

fn miio_ask_command(hardware: &str) -> Option<&'static str> {
    match hardware {
        "L05B" | "L05C" | "LX04" => Some("5-4"),
        "LX06" | "S12" | "S12A" | "LX01" | "L06A" | "LX05A" | "LX5A" | "L07A" => Some("5-5"),
        "L17A" | "X08E" | "L15A" | "X6A" | "X10A" => Some("7-4"),
        _ => None,
    }
}

fn parse_miio_action(command: &str) -> crate::Result<(u32, u32)> {
    let Some((siid, aiid)) = command.split_once('-') else {
        return Err(Error::Login(format!("无法识别的 MiIO 动作命令: {command}")));
    };
    let siid = siid
        .parse()
        .map_err(|_| Error::Login(format!("无法识别的 MiIO siid: {command}")))?;
    let aiid = aiid
        .parse()
        .map_err(|_| Error::Login(format!("无法识别的 MiIO aiid: {command}")))?;

    Ok((siid, aiid))
}

fn sign_miio_data(uri: &str, data: &str, ssecurity: &str) -> crate::Result<MiioSignedPayload> {
    let nonce = miio_nonce();
    let snonce = sign_nonce(ssecurity, &nonce)?;
    let msg = [
        uri,
        snonce.as_str(),
        nonce.as_str(),
        &format!("data={data}"),
    ]
    .join("&");
    let key = decode_base64(&snonce)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|error| Error::Login(format!("MiIO HMAC 初始化失败: {error}")))?;
    mac.update(msg.as_bytes());
    let signature = Base64::encode_string(&mac.finalize().into_bytes());

    Ok(MiioSignedPayload {
        _nonce: nonce,
        data: data.to_owned(),
        signature,
    })
}

fn sign_nonce(ssecurity: &str, nonce: &str) -> crate::Result<String> {
    let mut sha = Sha256::new();
    sha.update(decode_base64(ssecurity)?);
    sha.update(decode_base64(nonce)?);

    Ok(Base64::encode_string(&sha.finalize()))
}

fn miio_nonce() -> String {
    let mut nonce = Vec::with_capacity(12);
    nonce.extend_from_slice(&rand::random::<[u8; 8]>());
    let minutes = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 60;
    nonce.extend_from_slice(&(minutes as u32).to_be_bytes());

    Base64::encode_string(&nonce)
}

fn decode_base64(value: &str) -> crate::Result<Vec<u8>> {
    Base64::decode_vec(value).map_err(|error| Error::Login(format!("Base64 解码失败: {error}")))
}

fn decode_account_json(bytes: &[u8]) -> crate::Result<Value> {
    if bytes.len() < 11 {
        return Err(Error::Login("小米账号响应过短".to_owned()));
    }

    Ok(serde_json::from_slice(&bytes[11..])?)
}

fn parse_service_auth_response(response: Value) -> crate::Result<ServiceAuthResponse> {
    serde_json::from_value(response.clone()).map_err(|_| {
        Error::Login(format!(
            "当前登录状态无法直接换取 xiaomiio token，请重新登录: {response}"
        ))
    })
}

fn account_client_sign(ssecurity: &str, nonce: &serde_json::Number) -> String {
    let mut sha = Sha1::new();
    sha.update(format!("nonce={nonce}&{ssecurity}"));

    Base64::encode_string(&sha.finalize())
}

fn miio_response(response: Value) -> XiaoaiResponse {
    let code = response.get("code").and_then(Value::as_i64).unwrap_or(-1);
    let message = response
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("MiIO 请求已完成")
        .to_owned();

    XiaoaiResponse {
        code,
        message,
        data: response,
    }
}

fn is_auth_error(error: &Error) -> bool {
    match error {
        Error::Login(message) => message.contains("未授权") || message.contains("auth"),
        Error::Reqwest(error) => error.status() == Some(reqwest::StatusCode::UNAUTHORIZED),
        _ => false,
    }
}

fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;

    Ok(value.and_then(|value| match value {
        Value::Null => None,
        Value::String(value) => Some(value),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        other => Some(other.to_string()),
    }))
}
