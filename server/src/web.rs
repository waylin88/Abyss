use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::agent_manager::{AgentInfo, AgentManager};

pub async fn run(manager: Arc<AgentManager>, addr: &str) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/agents", get(list_agents))
        .route("/api/exec", post(exec_cmd))
        .route("/api/forward", post(do_forward))
        .with_state(manager);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn list_agents(State(mgr): State<Arc<AgentManager>>) -> Json<Vec<AgentInfo>> {
    Json(mgr.list().await)
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
    State(mgr): State<Arc<AgentManager>>,
    Json(req): Json<ExecReq>,
) -> impl IntoResponse {
    match mgr.exec(&req.agent, &req.cmd).await {
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
    local_port: u16,
    server_port: u16,
    #[serde(default = "default_host")]
    local_host: String,
}

fn default_host() -> String {
    "127.0.0.1".into()
}

async fn do_forward(
    State(mgr): State<Arc<AgentManager>>,
    Json(req): Json<ForwardReq>,
) -> impl IntoResponse {
    let local_addr = format!("{}:{}", req.local_host, req.local_port);
    match mgr.forward(&req.agent, &local_addr, req.server_port).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "msg": format!("映射已启动: 0.0.0.0:{} -> agent:{}", req.server_port, local_addr)
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "err": e.to_string()})),
        ),
    }
}