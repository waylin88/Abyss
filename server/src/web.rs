use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;

use crate::agent_manager::AgentManager;

#[derive(Clone)]
struct AppState {
    manager: Arc<AgentManager>,
    password: Arc<String>,
}

pub async fn run(manager: Arc<AgentManager>, addr: &str, password: &str) -> anyhow::Result<()> {
    let state = AppState {
        manager,
        password: Arc::new(password.to_string()),
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
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------- auth helper ----------

fn check_auth(headers: &HeaderMap, password: &str) -> bool {
    if password.is_empty() {
        return true;
    }
    // Check Authorization header (Bearer token from JS)
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            let expected = format!("Bearer {}", password);
            if auth_str == expected {
                return true;
            }
        }
    }
    // Fallback: check cookie (auto-sent by browser)
    if let Some(cookie) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("token=") {
                    return val == password;
                }
            }
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
        let cookie = format!(
            "token={}; Path=/; Max-Age=86400; SameSite=Lax",
            &*state.password
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie).unwrap(),
        );
        (
            StatusCode::OK,
            headers,
            Json(serde_json::json!({"ok": true, "token": &*state.password})),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            HeaderMap::new(),
            Json(serde_json::json!({"ok": false, "err": "密码错误"})),
        )
    }
}

async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_auth(&headers, &state.password) {
        return unauth();
    }
    (StatusCode::OK, Json(serde_json::json!(state.manager.list().await)))
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
    if !check_auth(&headers, &state.password) {
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
}

fn default_host() -> String {
    "127.0.0.1".into()
}

async fn do_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ForwardReq>,
) -> impl IntoResponse {
    if !check_auth(&headers, &state.password) {
        return unauth();
    }
    let name = req.agent_name.unwrap_or_default();
    let local_addr = format!("{}:{}", req.local_host, req.local_port);
    match state
        .manager
        .forward(&req.agent, &name, &local_addr, req.server_port)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "msg": format!("映射已启动: 0.0.0.0:{} -> {}:{}", req.server_port, req.agent, local_addr)
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "err": e.to_string()})),
        ),
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
    if !check_auth(&headers, &state.password) {
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
    if !check_auth(&headers, &state.password) {
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
    if !check_auth(&headers, &state.password) {
        return unauth();
    }
    let ok = state.manager.ping_agent(&req.agent).await;
    (StatusCode::OK, Json(serde_json::json!({"ok": ok})))
}