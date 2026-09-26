use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::agent_manager::{AgentInfo, AgentManager, ForwardInfo};

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
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            let expected = format!("Bearer {}", password);
            return auth_str == expected;
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
        Json(serde_json::json!({"ok": true, "token": &*state.password}))
    } else {
        (
            StatusCode::UNAUTHORIZED,
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
    (StatusCode::OK, Json(state.manager.list().await))
}

#[derive(Deserialize)]
struct ExecReq {
    agent: String,
    cmd: String,
}

#[derive(Serialize)]
struct ExecResp {
    code: i32,
    output: String,
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
            Json(ExecResp { code: r.code, output: r.output }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ExecResp {
                code: -1,
                output: e.to_string(),
            }),
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
    (StatusCode::OK, Json(state.manager.list_forwards().await))
}