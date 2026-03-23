use std::{
    env,
    fmt::Display,
    fs::{self, File},
    io::{self, BufReader},
    mem::take,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow, ensure};
use clap::{Parser, Subcommand};
use inquire::{Confirm, Password, PasswordDisplayMode, Select, Text};
use miai::{
    DeviceInfo, Error as MiaiError, PlayState, Xiaoai,
    conversation::AnswerPayload,
    login::{CaptchaChallenge, Login, LoginResponse, LoginStep, VerificationChallenge},
};
use once_cell::unsync::OnceCell;
use qrcode::{EcLevel, QrCode, render::unicode};
use serde_json::Value;
use time::{OffsetDateTime, UtcOffset};
use tracing_subscriber::EnvFilter;
use url::Url;

const DEFAULT_AUTH_FILE: &str = "xiaoai-auth.json";

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();

    if let Commands::Login { qr } = &cli.command {
        let xiaoai = if *qr {
            prompt_qr_login().await?
        } else {
            prompt_login().await?
        };
        save_auth_file(&cli.auth_file, &xiaoai)?;
        return Ok(());
    }

    // 之后的命令需要登录
    let xiaoai = cli.xiaoai()?;
    if let Commands::Device = cli.command {
        let device_info = cli.device_info().await?;
        for (i, info) in device_info.iter().enumerate() {
            if i != 0 {
                println!();
            }
            print!("{}", DisplayDeviceInfo(info));
        }
        return Ok(());
    }

    // 之后的命令需要设备 ID
    let device_id = cli.device_id().await?;
    if let Commands::History { limit } = cli.command {
        let info = cli
            .device_info()
            .await?
            .iter()
            .find(|x| x.device_id == device_id)
            .ok_or_else(|| anyhow!("找不到设备 `{device_id}` 的信息"))?;
        let mut records = xiaoai
            .conversations(device_id, &info.hardware, OffsetDateTime::now_utc(), limit)
            .await?
            .records;
        // 尝试换算成本地时间偏移
        if let Ok(offset) = UtcOffset::current_local_offset() {
            for record in &mut records {
                record.time = record.time.to_offset(offset);
            }
        }
        for (i, mut record) in records.into_iter().enumerate() {
            if i != 0 {
                println!();
            }
            println!("提问: {}", record.query);
            // 目前只解析第一个应答
            if let Some(answer) = record.answers.first_mut() {
                print!("应答: ");
                match &mut answer.payload {
                    AnswerPayload::Tts { text, .. } => println!("{text}"),
                    AnswerPayload::Llm { text, .. } => println!("{text}"),
                    AnswerPayload::Unknown(payload) => println!("{}", Value::Object(take(payload))),
                    _ => println!(),
                }
                println!("类型: {}", answer.kind);
            }
            println!("ID:   {}", record.request_id);
            println!("时间: {}", record.time);
        }
        return Ok(());
    }

    // 处理剩下的命令
    let response = match &cli.command {
        Commands::Say { text } => xiaoai.tts(device_id, text).await?,
        Commands::Play { url } => {
            if let Some(url) = url {
                xiaoai.play_url(device_id, url.as_str()).await?
            } else {
                xiaoai.set_play_state(device_id, PlayState::Play).await?
            }
        }
        Commands::Volume { volume } => xiaoai.set_volume(device_id, *volume).await?,
        Commands::Ask { text } => xiaoai.nlp(device_id, text).await?,
        Commands::Pause => xiaoai.set_play_state(device_id, PlayState::Pause).await?,
        Commands::Stop => xiaoai.set_play_state(device_id, PlayState::Stop).await?,
        Commands::Ubus {
            path,
            method,
            message,
        } => xiaoai.ubus_call(device_id, path, method, message).await?,
        cmd => unreachable!("命令 `{:?}` 应该被处理", cmd),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    if let Err(error) = persist_auth_file(&cli.auth_file, xiaoai) {
        eprintln!("警告: 更新认证缓存失败: {error}");
    }

    Ok(())
}

async fn prompt_login() -> anyhow::Result<Xiaoai> {
    let username = Text::new("账号:").prompt()?;
    let password = Password::new("密码:")
        .with_display_toggle_enabled()
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .with_help_message("CTRL + R 显示/隐藏密码")
        .prompt()?;
    let login = Login::new(&username, &password)?;
    let mut pending = None;

    let auth_response = loop {
        match pending.take() {
            Some(PendingAuth::Captcha(login_response, challenge)) => {
                let captcha = prompt_captcha(&challenge)?;
                match login
                    .auth_with_captcha(login_response.clone(), &challenge, &captcha)
                    .await
                {
                    Ok(auth_response) => break auth_response,
                    Err(MiaiError::NeedCaptcha(challenge)) => {
                        pending = Some(PendingAuth::Captcha(login_response, challenge));
                    }
                    Err(MiaiError::NeedVerification(challenge)) => {
                        prompt_verification(&login, &challenge).await?;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
            _ => match login.begin().await? {
                LoginStep::Authenticated(auth_response) => break auth_response,
                LoginStep::NeedAuth(login_response) => {
                    match login.auth(login_response.clone()).await {
                        Ok(auth_response) => break auth_response,
                        Err(MiaiError::NeedCaptcha(challenge)) => {
                            pending = Some(PendingAuth::Captcha(login_response, challenge));
                        }
                        Err(MiaiError::NeedVerification(challenge)) => {
                            prompt_verification(&login, &challenge).await?;
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
            },
        }
    };

    login.get_token(auth_response).await?;

    Ok(Xiaoai::from_login(login)?)
}

async fn prompt_qr_login() -> anyhow::Result<Xiaoai> {
    let login = Login::new_qr()?;
    let challenge = login.qr_challenge().await?;
    println!("请使用米家 APP 扫描下方二维码完成登录。");
    print_qr_code(&challenge.login_url)?;
    println!("扫码链接: {}", challenge.login_url);
    println!("二维码图片地址: {}", challenge.qr_url);
    println!("等待扫码确认...");
    login.wait_for_qr_scan(&challenge).await?;

    Ok(Xiaoai::from_login(login)?)
}

fn save_auth_file(auth_file: &PathBuf, xiaoai: &Xiaoai) -> anyhow::Result<()> {
    let can_save = if auth_file.exists() {
        Confirm::new(&format!("{} 已存在，是否覆盖?", auth_file.display())).prompt()?
    } else {
        true
    };

    if can_save {
        persist_auth_file(auth_file, xiaoai)?;
    }

    Ok(())
}

fn persist_auth_file(auth_file: &PathBuf, xiaoai: &Xiaoai) -> anyhow::Result<()> {
    let mut file = File::create(auth_file)?;
    xiaoai.save(&mut file).map_err(anyhow::Error::from_boxed)?;

    Ok(())
}

fn prompt_captcha(challenge: &CaptchaChallenge) -> anyhow::Result<String> {
    let path = write_captcha_image(challenge)?;
    println!("登录需要图片验证码。");
    println!("验证码图片已保存到: {}", path.display());
    println!("验证码地址: {}", challenge.url);

    Text::new("图片验证码:")
        .with_help_message("打开图片后输入看到的验证码")
        .prompt()
        .map_err(Into::into)
}

async fn prompt_verification(
    login: &Login,
    challenge: &VerificationChallenge,
) -> anyhow::Result<()> {
    println!("登录需要二次验证。");
    println!("验证地址: {}", challenge.url);
    let ticket = Text::new("二次验证码:")
        .with_help_message("输入手机或邮箱收到的验证码")
        .prompt()?;
    login.submit_verification(challenge, &ticket).await?;

    Ok(())
}

fn write_captcha_image(challenge: &CaptchaChallenge) -> anyhow::Result<PathBuf> {
    let extension = match challenge.content_type.as_deref() {
        Some("image/jpeg") => "jpg",
        Some("image/gif") => "gif",
        Some("image/webp") => "webp",
        _ => "png",
    };
    let filename = format!("miai-captcha-{}.{}", unix_millis(), extension);
    let path = env::temp_dir().join(filename);
    fs::write(&path, &challenge.image)?;

    Ok(path)
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

enum PendingAuth {
    Captcha(LoginResponse, CaptchaChallenge),
}

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// 指定认证文件
    #[arg(long, default_value = DEFAULT_AUTH_FILE)]
    auth_file: PathBuf,

    /// 指定设备 ID
    #[arg(short, long)]
    device_id: Option<String>,

    #[arg(skip)]
    xiaoai: OnceCell<Xiaoai>,

    #[arg(skip)]
    device_info: tokio::sync::OnceCell<Vec<DeviceInfo>>,
}

impl Cli {
    /// 加载 [`Xiaoai`]，仅加载一次然后缓存起来。
    fn xiaoai(&self) -> anyhow::Result<&Xiaoai> {
        self.xiaoai.get_or_try_init(|| {
            let file = File::open(&self.auth_file)
                .with_context(|| format!("需要可用的认证文件 `{}`", self.auth_file.display()))?;

            Xiaoai::load(BufReader::new(file))
                .map_err(anyhow::Error::from_boxed)
                .with_context(|| format!("加载认证文件 `{}` 失败", self.auth_file.display()))
        })
    }

    /// 获取设备信息，仅获取一次然后缓存起来。
    async fn device_info(&self) -> anyhow::Result<&Vec<DeviceInfo>> {
        self.device_info
            .get_or_try_init(async || {
                self.xiaoai()?
                    .device_info()
                    .await
                    .context("获取设备列表失败")
            })
            .await
    }

    /// 获取用户指定的设备 ID。
    ///
    /// 如果用户没有在命令行指定，则会向服务器请求设备列表。
    /// 如果请求结果只有一个设备，会自动选择这个唯一的设备。
    /// 如果请求结果存在多个设备，则会让用户自行选择。
    async fn device_id(&self) -> anyhow::Result<&str> {
        if let Some(device_id) = &self.device_id {
            return Ok(device_id);
        }

        let info = self.device_info().await?;
        ensure!(!info.is_empty(), "无可用设备，需要在小米音箱 APP 中绑定");
        if info.len() == 1 {
            return Ok(info[0].device_id.as_str());
        }

        let options = info.iter().map(DisplayDeviceInfo).collect();
        let ans = Select::new("目标设备?", options).prompt()?;

        Ok(&ans.0.device_id)
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// 登录以获得认证
    Login {
        /// 使用二维码扫码登录
        #[arg(long)]
        qr: bool,
    },
    /// 列出设备
    Device,
    /// 播报文本
    Say { text: String },
    /// 播放
    Play {
        /// 可选的音乐链接
        url: Option<Url>,
    },
    /// 暂停
    Pause,
    /// 停止
    Stop,
    /// 调整音量
    Volume { volume: u32 },
    /// 询问
    Ask { text: String },
    /// 对话记录
    History {
        /// 最大条数
        #[arg(short = 'n', long, default_value_t = 1)]
        limit: u32,
    },
    /// OpenWrt UBUS call
    Ubus {
        path: String,
        method: String,
        message: String,
    },
}

fn print_qr_code(content: &str) -> anyhow::Result<()> {
    let qr = QrCode::with_error_correction_level(content.as_bytes(), EcLevel::L)?;
    let columns = terminal_columns();
    let width_with_quiet_zone = qr.width() + 8;
    let use_quiet_zone = columns.is_none_or(|columns| columns >= width_with_quiet_zone);
    let text = qr
        .render::<unicode::Dense1x2>()
        .quiet_zone(use_quiet_zone)
        .module_dimensions(1, 1)
        .build();
    if let Some(columns) = columns
        && columns < qr.width()
    {
        eprintln!(
            "提示: 当前终端宽度只有 {columns} 列，二维码仍可能换行；建议放大终端，或直接打开下方扫码链接。"
        );
    }
    println!("{text}");

    Ok(())
}

fn terminal_columns() -> Option<usize> {
    env::var("COLUMNS").ok()?.parse().ok()
}

struct DisplayDeviceInfo<'a>(&'a DeviceInfo);

impl Display for DisplayDeviceInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "名称: {}", self.0.name)?;
        writeln!(f, "ID:   {}", self.0.device_id)?;
        writeln!(f, "机型: {}", self.0.hardware)
    }
}
