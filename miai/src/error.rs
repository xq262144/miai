use crate::{
    XiaoaiResponse,
    login::{CaptchaChallenge, VerificationChallenge},
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("API 返回 {}: {}", .0.code, .0.message)]
    Api(XiaoaiResponse),

    #[error("登录需要图片验证码")]
    NeedCaptcha(CaptchaChallenge),

    #[error("登录需要二次验证")]
    NeedVerification(VerificationChallenge),

    #[error("登录失败: {0}")]
    Login(String),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Cookie(#[from] cookie_store::CookieError),

    #[error(transparent)]
    Url(#[from] url::ParseError),
}
