use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::agent_manager::AgentManager;

#[derive(Clone)]
struct AppState {
    manager: Arc<AgentManager>,
    password: Arc<String>,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    domain: Arc<Mutex<String>>,
    data_dir: PathBuf,
}

#[derive(Serialize, Deserialize, Clone)]
struct ServerConfig {
    domain: String,
}

impl ServerConfig {
    fn load(data_dir: &std::path::Path) -> Self {
        let path = data_dir.join("config.json");
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<ServerConfig>(&content) {
                return cfg;
            }
        }
        ServerConfig {
            domain: String::new(),
        }
    }

    fn save(&self, data_dir: &std::path::Path) {
        let path = data_dir.join("config.json");
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, content);
        }
    }
}

pub async fn run(
    manager: Arc<AgentManager>,
    addr: &str,
    password: &str,
) -> anyhow::Result<()> {
    // Ensure data directory exists (./data by default)
    let data_path = PathBuf::from("./data");
    let _ = std::fs::create_dir_all(&data_path);

    // Load config from file (no CLI override)
    let cfg = ServerConfig::load(&data_path);
    let domain = Arc::new(Mutex::new(cfg.domain.clone()));

    let sessions = Arc::new(Mutex::new(HashMap::new()));

    // Spawn periodic session cleanup (every 30 minutes)
    let cleanup_sessions = sessions.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30 * 60)).await;
            let mut map = cleanup_sessions.lock().await;
            map.retain(|_, expires| *expires > Instant::now());
        }
    });

    let state = AppState {
        manager,
        password: Arc::new(password.to_string()),
        sessions,
        domain,
        data_dir: data_path,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/login", post(api_login))
        .route("/api/agents", get(list_agents))
        .route("/api/exec", post(exec_cmd))
        .route("/api/ping", post(api_ping))
        .route("/api/forward", post(do_forward))
        .route("/api/forward/stop", post(stop_forward))
        .route("/api/forwards", get(list_forwards))
        .route("/api/config", get(get_config).post(set_config))
        .route("/api/web/select", post(api_web_select))
        .with_state(state);

    let listener = crate::agent_manager::bind_listener(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------- session & auth ----------

/// Generate a random-looking session token using time + atomic counter.
fn generate_session_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let combined = (now as u64)
        .wrapping_mul(3_141_592_653_589_793_239u64)
        .wrapping_add(count);
    format!("sess-{:016x}", combined)
}

async fn check_auth(headers: &HeaderMap, sessions: &Mutex<HashMap<String, Instant>>) -> bool {
    // Helper: extract session token from Cookie header
    fn cookie_token(headers: &HeaderMap) -> Option<&str> {
        if let Some(cookie) = headers.get(header::COOKIE) {
            if let Ok(cookie_str) = cookie.to_str() {
                for part in cookie_str.split(';') {
                    let part = part.trim();
                    if let Some(val) = part.strip_prefix("token=") {
                        return Some(val.trim());
                    }
                }
            }
        }
        None
    }

    let token = if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(val) = auth_str.strip_prefix("Bearer ") {
                Some(val.trim())
            } else {
                cookie_token(headers)
            }
        } else {
            None
        }
    } else {
        cookie_token(headers)
    };

    if let Some(t) = token {
        let map = sessions.lock().await;
        if let Some(expires) = map.get(t) {
            return *expires > Instant::now();
        }
    }
    false
}

fn unauth() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"ok": false, "err": "需要登录"})),
    )
}

// ---------- routes ----------

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

#[derive(Deserialize)]
struct LoginReq {
    password: String,
}

async fn api_login(
    State(state): State<AppState>,
    Json(req): Json<LoginReq>,
) -> impl IntoResponse {
    if req.password == *state.password {
        let session_token = generate_session_token();
        let mut map = state.sessions.lock().await;
        map.insert(session_token.clone(), Instant::now() + Duration::from_secs(86400));

        let cookie = format!(
            "token={}; Path=/; Max-Age=86400; SameSite=Lax; HttpOnly",
            session_token
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie).unwrap(),
        );
        (
            StatusCode::OK,
            headers,
            Json(serde_json::json!({"ok": true, "token": session_token})),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            HeaderMap::new(),
            Json(serde_json::json!({"ok": false, "err": "密码错误"})),
        )
    }
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    if !state.password.is_empty() && !check_auth(&headers, &state.sessions).await {
        return unauth();
    }
    let q = query.q.unwrap_or_default();
    (StatusCode::OK, Json(serde_json::json!(state.manager.list_all(&q).await)))
}

#[derive(Deserialize)]
struct ExecReq {
    agent: String,
    cmd: String,
}

async fn exec_cmd(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ExecReq>,
) -> impl IntoResponse {
    if !state.password.is_empty() && !check_auth(&headers, &state.sessions).await {
        return unauth();
    }
    match state.manager.exec(&req.agent, &req.cmd).await {
        Ok(r) => (
            StatusCode::OK,
            Json(serde_json::json!({"code": r.code, "output": r.output})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"code": -1, "output": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
struct ForwardReq {
    agent: String,
    agent_name: Option<String>,
    local_port: u16,
    server_port: u16,
    #[serde(default = "default_host")]
    local_host: String,
    #[serde(default)]
    force: bool,
}

fn default_host() -> String {
    "127.0.0.1".into()
}

async fn do_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ForwardReq>,
) -> impl IntoResponse {
    if !state.password.is_empty() && !check_auth(&headers, &state.sessions).await {
        return unauth();
    }
    let name = req.agent_name.unwrap_or_default();
    let local_addr = format!("{}:{}", req.local_host, req.local_port);
    match state
        .manager
        .forward(&req.agent, &name, &local_addr, req.server_port, req.force)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "msg": format!("映射已启动: 0.0.0.0:{} -> {}:{}", req.server_port, req.agent, local_addr)
            })),
        ),
        Err(e) => {
            let err = e.to_string();
            if let Some(details) = err.strip_prefix("PORT_CONFLICT:") {
                let parts: Vec<&str> = details.split(':').collect();
                if parts.len() == 4 {
                    return (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "ok": false,
                            "conflict": true,
                            "forward_id": parts[0],
                            "agent_id": parts[1],
                            "agent_name": parts[2],
                            "local_addr": parts[3],
                        })),
                    );
                }
            }
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "err": err})),
            )
        }
    }
}

#[derive(Deserialize)]
struct StopForwardReq {
    id: String,
}

async fn stop_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StopForwardReq>,
) -> impl IntoResponse {
    if !state.password.is_empty() && !check_auth(&headers, &state.sessions).await {
        return unauth();
    }
    match state.manager.stop_forward(&req.id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "msg": "映射已停止"})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "err": e.to_string()})),
        ),
    }
}

async fn list_forwards(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.password.is_empty() && !check_auth(&headers, &state.sessions).await {
        return unauth();
    }
    (StatusCode::OK, Json(serde_json::json!(state.manager.list_forwards().await)))
}

#[derive(Deserialize)]
struct PingReq {
    agent: String,
}

async fn api_ping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PingReq>,
) -> impl IntoResponse {
    if !state.password.is_empty() && !check_auth(&headers, &state.sessions).await {
        return unauth();
    }
    let ok = state.manager.ping_agent(&req.agent).await;
    (StatusCode::OK, Json(serde_json::json!({"ok": ok})))
}

#[derive(Deserialize)]
struct WebSelectReq {
    agent: String,
}

/// Select the currently active web proxy agent.
/// Only this agent's port 80 will be accessible via the HTTP proxy (port 18080).
async fn api_web_select(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<WebSelectReq>,
) -> impl IntoResponse {
    if !state.password.is_empty() && !check_auth(&headers, &state.sessions).await {
        return unauth();
    }
    state.manager.set_web_agent(&req.agent).await;
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ---------- Config ----------

async fn get_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.password.is_empty() && !check_auth(&headers, &state.sessions).await {
        return unauth();
    }
    let domain = state.domain.lock().await.clone();
    (
        StatusCode::OK,
        Json(serde_json::json!({"domain": domain})),
    )
}

#[derive(Deserialize)]
struct SetConfigReq {
    domain: Option<String>,
}

async fn set_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SetConfigReq>,
) -> impl IntoResponse {
    if !state.password.is_empty() && !check_auth(&headers, &state.sessions).await {
        return unauth();
    }
    if let Some(domain) = req.domain {
        let cfg = ServerConfig {
            domain: domain.clone(),
        };
        cfg.save(&state.data_dir);
        let mut cur = state.domain.lock().await;
        *cur = domain;
    }
    let domain = state.domain.lock().await.clone();
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "domain": domain})),
    )
}