mod agent_manager;
mod web;

use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "rtrserver", version, about = "Router remote management server")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:9527")]
    agent_addr: String,

    #[arg(long, default_value = "0.0.0.0:8080")]
    web_addr: String,

    #[arg(long, default_value = "")]
    token: String,

    #[arg(long, default_value = "")]
    password: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let manager = Arc::new(agent_manager::AgentManager::new());

    let mgr = manager.clone();
    let addr = cli.agent_addr.clone();
    let token = cli.token.clone();
    tokio::spawn(async move {
        if let Err(e) = agent_manager::run_agent_listener(mgr, &addr, &token).await {
            eprintln!("[server] agent listener error: {}", e);
        }
    });

    let web_addr = cli.web_addr.clone();
    println!("[server] agent protocol on {}", cli.agent_addr);
    println!("[server] web UI on      http://{}", web_addr);
    if !cli.token.is_empty() {
        println!("[server] agent token:   {}", cli.token);
    }
    if !cli.password.is_empty() {
        println!("[server] web password:  {} (login required)", cli.password);
    }

    web::run(manager, &web_addr, &cli.password).await?;
    Ok(())
}