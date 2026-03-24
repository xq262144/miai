use std::{
    collections::VecDeque,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use anyhow::{Context, anyhow, ensure};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute, queue,
    terminal::{
        self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use miai::{
    DeviceInfo, PlayState, Xiaoai,
    conversation::{AnswerPayload, Record},
};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::{
    sync::mpsc,
    time::{Duration, MissedTickBehavior},
};
use time::{OffsetDateTime, UtcOffset};

use crate::{Cli, persist_auth_file};

const CHAT_SYSTEM_PROMPT: &str =
    "你是在小爱音箱上自动回复用户的语音助手。请直接输出适合中文语音播报的自然回答，简洁、明确，不要 Markdown，不要代码块。";

pub async fn run_serve(
    cli: &Cli,
    interval_secs: f32,
    mute_reply: bool,
    chat: bool,
) -> anyhow::Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "`serve` 需要在交互式终端中运行"
    );

    let xiaoai = cli.xiaoai()?.clone();
    let auth_file = cli.auth_file.clone();
    let device_id = cli.device_id().await?.to_owned();
    let device = cli
        .device_info()
        .await?
        .iter()
        .find(|info| info.device_id == device_id)
        .cloned()
        .ok_or_else(|| anyhow!("找不到设备 `{device_id}` 的信息"))?;

    let local_offset = UtcOffset::current_local_offset().ok();
    let mut last_seen = current_latest_marker(&xiaoai, &device).await;
    let chat_config = if chat {
        Some(OpencodeChat::load()?)
    } else {
        None
    };
    let mut ui = ServeUi::new(device.clone(), interval_secs.max(1.0), mute_reply, chat_config.as_ref());
    ui.push_info("进入 serve 模式");
    ui.push_info("新消息会显示在日志区，当前输入不会被打断");
    ui.push_info("纯文本直接播报，支持 /say、/mute on|off、/help、/quit");
    if let Some(chat_config) = &chat_config {
        ui.push_info(format!("自动回复已开启: {}", chat_config.model));
    }

    let mut terminal = ServeTerminal::enter()?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let _input = InputReader::spawn(tx.clone());
    let _chat_worker = chat_config.as_ref().map(|chat_config| {
        ChatWorker::spawn(
            chat_config.clone(),
            tx.clone(),
            xiaoai.clone(),
            auth_file.clone(),
            device_id.clone(),
        )
    });

    let mut ticker = tokio::time::interval(Duration::from_secs_f32(ui.interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ui.render(&mut terminal)?;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match poll_records(&xiaoai, &device, &mut last_seen, ui.mute_reply, local_offset).await {
                    Ok(records) => {
                        if records.is_empty() {
                            ui.push_info("轮询: 无新消息");
                        } else {
                            ui.push_info(format!("轮询: 捕获 {} 条新记录", records.len()));
                        }
                        for record in records {
                            ui.push_record(&record, local_offset);
                            if ui.chat_enabled {
                                if let Some(query) = record_to_chat_query(&record) {
                                    let _ = tx.send(AppEvent::ChatRequest(query.to_owned()));
                                }
                            }
                        }
                    }
                    Err(error) => ui.push_error(format!("轮询失败: {error}")),
                }
                ui.render(&mut terminal)?;
            }
            event = rx.recv() => {
                let Some(event) = event else {
                    break;
                };
                match event {
                    AppEvent::Input(InputEvent::Key(key)) => {
                        match ui.handle_key(key) {
                            InputAction::None => {}
                            InputAction::Submit(line) => {
                                if let ControlFlow::Break = handle_input(
                                    &xiaoai,
                                    &auth_file,
                                    &device_id,
                                    &mut ui,
                                    line,
                                ).await? {
                                    break;
                                }
                            }
                            InputAction::Quit => break,
                        }
                    }
                    AppEvent::Input(InputEvent::Resize) => {}
                    AppEvent::ChatRequest(query) => {
                        if let Some(worker) = &_chat_worker {
                            worker.enqueue(query)?;
                        }
                    }
                    AppEvent::ChatLog(line) => ui.push_log(line),
                    AppEvent::ChatStatus(status) => ui.status = status,
                }
                ui.render(&mut terminal)?;
            }
        }
    }

    Ok(())
}

async fn handle_input(
    xiaoai: &Xiaoai,
    auth_file: &PathBuf,
    device_id: &str,
    ui: &mut ServeUi,
    line: String,
) -> anyhow::Result<ControlFlow> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(ControlFlow::Continue);
    }

    if matches!(line, "/quit" | "quit" | "/exit" | "exit") {
        return Ok(ControlFlow::Break);
    }

    if matches!(line, "/help" | "help") {
        ui.push_info("纯文本: 直接播报给小爱");
        ui.push_info("/say 文本: 播报文本");
        ui.push_info("/mute on|off: 打开或关闭自动暂停小爱回复");
        ui.push_info("/quit: 退出 serve");
        return Ok(ControlFlow::Continue);
    }

    if let Some(value) = line
        .strip_prefix("/mute ")
        .or_else(|| line.strip_prefix("mute "))
    {
        match value.trim() {
            "on" => {
                ui.mute_reply = true;
                ui.push_info("mute_reply 已开启");
            }
            "off" => {
                ui.mute_reply = false;
                ui.push_info("mute_reply 已关闭");
            }
            _ => ui.push_error("用法: /mute on|off"),
        }
        return Ok(ControlFlow::Continue);
    }

    let spoken = line
        .strip_prefix("/say ")
        .or_else(|| line.strip_prefix("say "))
        .unwrap_or(line)
        .trim();
    if spoken.is_empty() {
        return Ok(ControlFlow::Continue);
    }

    ui.push_local_say(spoken);
    ui.status = Some("发送播报中...".to_owned());
    let response = xiaoai.tts(device_id, spoken).await;
    ui.status = None;
    match response {
        Ok(response) => {
            ui.push_info(format!(
                "播报已发送: code={}, message={}",
                response.code, response.message
            ));
            if let Err(error) = persist_auth_file(auth_file, xiaoai) {
                ui.push_error(format!("更新认证缓存失败: {error}"));
            }
        }
        Err(error) => ui.push_error(format!("播报失败: {error}")),
    }

    Ok(ControlFlow::Continue)
}

async fn current_latest_marker(xiaoai: &Xiaoai, device: &DeviceInfo) -> Option<SeenRecord> {
    xiaoai
        .conversations(&device.device_id, &device.hardware, OffsetDateTime::now_utc(), 1)
        .await
        .ok()?
        .records
        .into_iter()
        .next()
        .map(|record| SeenRecord {
            request_id: record.request_id,
        })
}

async fn poll_records(
    xiaoai: &Xiaoai,
    device: &DeviceInfo,
    last_seen: &mut Option<SeenRecord>,
    mute_reply: bool,
    local_offset: Option<UtcOffset>,
) -> anyhow::Result<Vec<Record>> {
    let records = xiaoai
        .conversations(&device.device_id, &device.hardware, OffsetDateTime::now_utc(), 5)
        .await?
        .records;
    let mut unseen = Vec::new();

    for record in records {
        if last_seen
            .as_ref()
            .is_some_and(|seen| seen.request_id == record.request_id)
        {
            break;
        }
        unseen.push(record);
    }

    if unseen.is_empty() {
        return Ok(Vec::new());
    }

    unseen.reverse();
    if mute_reply {
        mute_xiaoai_reply(xiaoai, &device.device_id).await?;
    }

    if let Some(record) = unseen.last() {
        *last_seen = Some(SeenRecord {
            request_id: record.request_id.clone(),
        });
    }

    let mut normalized = Vec::with_capacity(unseen.len());
    for mut record in unseen {
        if let Some(offset) = local_offset {
            record.time = record.time.to_offset(offset);
        }
        normalized.push(record);
    }

    Ok(normalized)
}

async fn mute_xiaoai_reply(xiaoai: &Xiaoai, device_id: &str) -> anyhow::Result<()> {
    for _ in 0..8 {
        match xiaoai_is_playing(xiaoai, device_id).await {
            Ok(true) => {
                xiaoai
                    .set_play_state(device_id, PlayState::Pause)
                    .await
                    .with_context(|| "暂停小爱回复失败")?;
                return Ok(());
            }
            Ok(false) => {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Err(_) => break,
        }
    }

    xiaoai
        .set_play_state(device_id, PlayState::Pause)
        .await
        .with_context(|| "暂停小爱回复失败")?;

    Ok(())
}

async fn xiaoai_is_playing(xiaoai: &Xiaoai, device_id: &str) -> anyhow::Result<bool> {
    let response = xiaoai.player_status(device_id).await?;
    let info = response
        .data
        .get("info")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("播放器状态缺少 info"))?;
    let info: Value = serde_json::from_str(info)?;

    Ok(info.get("status").and_then(Value::as_i64) == Some(1))
}

struct ServeUi {
    device: DeviceInfo,
    interval_secs: f32,
    mute_reply: bool,
    chat_enabled: bool,
    chat_model: Option<String>,
    input: String,
    logs: VecDeque<String>,
    status: Option<String>,
}

impl ServeUi {
    fn new(
        device: DeviceInfo,
        interval_secs: f32,
        mute_reply: bool,
        chat_config: Option<&OpencodeChat>,
    ) -> Self {
        Self {
            device,
            interval_secs: interval_secs.max(1.0),
            mute_reply,
            chat_enabled: chat_config.is_some(),
            chat_model: chat_config.map(|config| config.model.clone()),
            input: String::new(),
            logs: VecDeque::new(),
            status: None,
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> InputAction {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                InputAction::Quit
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.input.clear();
                InputAction::None
            }
            KeyCode::Esc => InputAction::Quit,
            KeyCode::Enter => InputAction::Submit(std::mem::take(&mut self.input)),
            KeyCode::Backspace => {
                self.input.pop();
                InputAction::None
            }
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.input.push(ch);
                InputAction::None
            }
            _ => InputAction::None,
        }
    }

    fn push_record(&mut self, record: &Record, local_offset: Option<UtcOffset>) {
        let time = local_offset.map_or(record.time, |offset| record.time.to_offset(offset));
        self.push_log(format!("听到@{}: {}", time, record.query));
        if let Some(answer) = record_answer_text(record) {
            self.push_log(format!("小爱回复@{}: {}", time, answer));
        }
    }

    fn push_local_say(&mut self, text: &str) {
        self.push_log(format!(">>> 播报: {text}"));
    }

    fn push_info(&mut self, text: impl Into<String>) {
        self.push_log(format!("• {}", text.into()));
    }

    fn push_error(&mut self, text: impl Into<String>) {
        self.push_log(format!("! {}", text.into()));
    }

    fn push_log(&mut self, line: String) {
        self.logs.push_back(format!("[{}] {}", log_time(), line));
        while self.logs.len() > 1000 {
            self.logs.pop_front();
        }
    }

    fn render(&self, terminal: &mut ServeTerminal) -> anyhow::Result<()> {
        let (width, height) = terminal::size()?;
        let width = usize::from(width.max(20));
        let height = usize::from(height.max(8));
        let header = format!(
            "miai serve | {} ({}) | mute:{} | poll:{:.0}s | chat:{}",
            self.device.name,
            self.device.hardware,
            if self.mute_reply { "on" } else { "off" },
            self.interval_secs
            ,
            self.chat_model.as_deref().unwrap_or("off")
        );
        let status = self
            .status
            .as_deref()
            .unwrap_or("Ctrl+C 或 /quit 退出");
        let logs_height = height.saturating_sub(4);
        let lines = visible_log_lines(&self.logs, width, logs_height);
        let prompt = "say> ";
        let visible_input = tail_for_width(&self.input, width.saturating_sub(prompt.len()));
        let cursor_x = prompt.chars().count() + visible_input.chars().count();

        queue!(
            terminal.stdout,
            Hide,
            MoveTo(0, 0),
            Clear(ClearType::All),
        )?;
        write_line(&mut terminal.stdout, 0, &truncate_line(&header, width))?;
        write_line(
            &mut terminal.stdout,
            1,
            &truncate_line(&format!("状态: {status}"), width),
        )?;
        for (index, line) in lines.iter().enumerate() {
            write_line(&mut terminal.stdout, (index + 2) as u16, line)?;
        }
        let separator_y = height.saturating_sub(2) as u16;
        write_line(&mut terminal.stdout, separator_y, &"─".repeat(width))?;
        write_line(
            &mut terminal.stdout,
            separator_y + 1,
            &truncate_line(&format!("{prompt}{visible_input}"), width),
        )?;
        queue!(terminal.stdout, MoveTo(cursor_x as u16, separator_y + 1), Show)?;
        terminal.stdout.flush()?;

        Ok(())
    }
}

fn log_time() -> String {
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    now.time().to_string()
}

fn visible_log_lines(logs: &VecDeque<String>, width: usize, max_lines: usize) -> Vec<String> {
    let mut lines = logs
        .iter()
        .flat_map(|line| wrap_line(line, width))
        .collect::<Vec<_>>();
    if lines.len() > max_lines {
        let start = lines.len() - max_lines;
        lines.drain(0..start);
    }
    lines
}

fn wrap_line(line: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let chars = line.chars().collect::<Vec<_>>();
    if chars.is_empty() {
        out.push(String::new());
        return out;
    }
    for chunk in chars.chunks(width) {
        out.push(chunk.iter().collect());
    }
    out
}

fn truncate_line(line: &str, width: usize) -> String {
    line.chars().take(width).collect()
}

fn tail_for_width(line: &str, width: usize) -> String {
    let chars = line.chars().collect::<Vec<_>>();
    let start = chars.len().saturating_sub(width);
    chars[start..].iter().collect()
}

fn write_line(stdout: &mut io::Stdout, y: u16, line: &str) -> anyhow::Result<()> {
    queue!(stdout, MoveTo(0, y))?;
    write!(stdout, "{line}")?;
    Ok(())
}

fn record_answer_text(record: &Record) -> Option<&str> {
    let answer = record.answers.first()?;
    match &answer.payload {
        AnswerPayload::Tts { text, .. } => Some(text),
        AnswerPayload::Llm { text, .. } => Some(text),
        _ => None,
    }
}

struct ServeTerminal {
    stdout: io::Stdout,
}

impl ServeTerminal {
    fn enter() -> anyhow::Result<Self> {
        let mut stdout = io::stdout();
        enable_raw_mode()?;
        execute!(stdout, EnterAlternateScreen, Hide)?;
        Ok(Self { stdout })
    }
}

impl Drop for ServeTerminal {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.stdout, Show, LeaveAlternateScreen);
    }
}

struct InputReader {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl InputReader {
    fn spawn(tx: mpsc::UnboundedSender<AppEvent>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match event::poll(Duration::from_millis(100)) {
                    Ok(true) => match event::read() {
                        Ok(Event::Key(key)) => {
                            if tx.send(AppEvent::Input(InputEvent::Key(key))).is_err() {
                                break;
                            }
                        }
                        Ok(Event::Resize(_, _)) => {
                            if tx.send(AppEvent::Input(InputEvent::Resize)).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    },
                    Ok(false) => {}
                    Err(_) => break,
                }
            }
        });

        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for InputReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Clone, Debug)]
struct SeenRecord {
    request_id: String,
}

enum InputEvent {
    Key(KeyEvent),
    Resize,
}

enum InputAction {
    None,
    Submit(String),
    Quit,
}

enum ControlFlow {
    Continue,
    Break,
}

#[derive(Clone)]
struct OpencodeChat {
    model: String,
    api_key: String,
    base_url: String,
    client: Client,
}

impl OpencodeChat {
    fn load() -> anyhow::Result<Self> {
        let config = resolved_opencode_config().or_else(|_| load_opencode_config_files())?;

        let model = config
            .get("model")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("opencode 默认模型未配置"))?
            .to_owned();
        let (provider_name, model_name) = model
            .split_once('/')
            .ok_or_else(|| anyhow!("opencode 默认模型格式无效: {model}"))?;
        let providers = config
            .get("provider")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("opencode 配置中缺少 provider"))?;
        let (_, provider) = providers
            .iter()
            .find(|(key, value)| {
                *key == provider_name
                    || value.get("name").and_then(Value::as_str) == Some(provider_name)
            })
            .ok_or_else(|| anyhow!("找不到 opencode 默认 provider: {provider_name}"))?;
        let base_url = provider
            .get("options")
            .and_then(|value| value.get("baseURL"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("opencode provider 缺少 baseURL"))?
            .trim_end_matches('/')
            .to_owned();
        let api_key = provider
            .get("options")
            .and_then(|value| value.get("apiKey"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("opencode provider 缺少 api key"))?
            .to_owned();
        let client = Client::builder().build()?;

        Ok(Self {
            model: format!("{provider_name}/{model_name}"),
            api_key,
            base_url,
            client,
        })
    }

    async fn complete(&self, query: &str) -> anyhow::Result<String> {
        let model_name = self
            .model
            .split_once('/')
            .map(|(_, model)| model)
            .unwrap_or(self.model.as_str());
        let response: Value = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&json!({
                "model": model_name,
                "messages": [
                    {"role": "system", "content": CHAT_SYSTEM_PROMPT},
                    {"role": "user", "content": query}
                ]
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let content = response
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("completion 响应缺少内容"))?;

        Ok(content.to_owned())
    }
}

fn resolved_opencode_config() -> anyhow::Result<Value> {
    let output = Command::new("opencode")
        .args(["debug", "config"])
        .output()
        .context("执行 `opencode debug config` 失败")?;
    ensure!(
        output.status.success(),
        "`opencode debug config` 失败: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn load_opencode_config_files() -> anyhow::Result<Value> {
    let home = std::env::var("HOME").context("无法读取 HOME")?;
    let config_path = PathBuf::from(&home).join(".config/opencode/opencode.json");
    let auth_path = PathBuf::from(&home).join(".local/share/opencode/auth.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path).with_context(|| {
        format!("读取 opencode 配置失败: {}", config_path.display())
    })?)?;
    let auth: Value = serde_json::from_slice(&std::fs::read(&auth_path).with_context(|| {
        format!("读取 opencode 认证失败: {}", auth_path.display())
    })?)?;
    if let Some(providers) = config.get_mut("provider").and_then(Value::as_object_mut) {
        if let Some(auth_entries) = auth.as_object() {
            for (provider_key, provider_value) in providers {
                let Some(entry) = auth_entries.get(provider_key) else {
                    continue;
                };
                let Some(key) = entry.get("key").and_then(Value::as_str) else {
                    continue;
                };
                if let Some(options) = provider_value
                    .get_mut("options")
                    .and_then(Value::as_object_mut)
                {
                    options
                        .entry("apiKey".to_owned())
                        .or_insert_with(|| Value::String(key.to_owned()));
                }
            }
        }
    }

    Ok(config)
}

struct ChatWorker {
    tx: mpsc::UnboundedSender<String>,
}

impl ChatWorker {
    fn spawn(
        chat: OpencodeChat,
        ui_tx: mpsc::UnboundedSender<AppEvent>,
        xiaoai: Xiaoai,
        auth_file: PathBuf,
        device_id: String,
    ) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(query) = rx.recv().await {
                let _ = ui_tx.send(AppEvent::ChatStatus(Some("AI 正在思考...".to_owned())));
                let _ = ui_tx.send(AppEvent::ChatLog(format!("<<< 用户: {query}")));
                match chat.complete(&query).await {
                    Ok(answer) => {
                        let _ = ui_tx.send(AppEvent::ChatLog(format!(">>> AI: {answer}")));
                        let _ = ui_tx.send(AppEvent::ChatStatus(Some("AI 回复中...".to_owned())));
                        match xiaoai.tts(&device_id, &answer).await {
                            Ok(_) => {
                                let _ = ui_tx.send(AppEvent::ChatLog("• AI 回复已播报".to_owned()));
                                if let Err(error) = persist_auth_file(&auth_file, &xiaoai) {
                                    let _ = ui_tx.send(AppEvent::ChatLog(format!("! 更新认证缓存失败: {error}")));
                                }
                            }
                            Err(error) => {
                                let _ = ui_tx.send(AppEvent::ChatLog(format!("! AI 回复播报失败: {error}")));
                            }
                        }
                    }
                    Err(error) => {
                        let _ = ui_tx.send(AppEvent::ChatLog(format!("! AI 自动回复失败: {error}")));
                    }
                }
                let _ = ui_tx.send(AppEvent::ChatStatus(None));
            }
        });

        Self { tx }
    }

    fn enqueue(&self, query: String) -> anyhow::Result<()> {
        self.tx
            .send(query)
            .map_err(|_| anyhow!("chat worker 已停止"))
    }
}

fn record_to_chat_query(record: &Record) -> Option<&str> {
    let query = record.query.trim();
    if query.is_empty() {
        None
    } else {
        Some(query)
    }
}

enum AppEvent {
    Input(InputEvent),
    ChatRequest(String),
    ChatLog(String),
    ChatStatus(Option<String>),
}
