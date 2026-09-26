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

    #[arg(long, default_value = "", help = "Comma-separated token whitelist. Only agents with these tokens are accepted. Empty = accept all.")]
    allow_tokens: String,

    #[arg(long, default_value = "", help = "Comma-separated token blacklist. Agents with these tokens are rejected.")]
    block_tokens: String,

    #[arg(long, default_value = "")]
    password: String,

    #[arg(long, default_value = "18080", help = "HTTP proxy auto-routing port. 0 = disabled. Routes requests by Host header to agent's port 80.")]
    http_proxy_port: u16,

    #[arg(long, default_value = "", help = "Domain suffix for HTTP proxy (e.g., dome.com). Requests with Host: <agent_id>.dome.com are routed to that agent.")]
    http_proxy_domain: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let allow: Vec<String> = if cli.allow_tokens.is_empty() {
        Vec::new()
    } else {
        cli.allow_tokens.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    };
    let block: Vec<String> = if cli.block_tokens.is_empty() {
        Vec::new()
    } else {
        cli.block_tokens.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    };

    let manager = Arc::new(agent_manager::AgentManager::new());

    let mgr = manager.clone();
    let addr = cli.agent_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = agent_manager::run_agent_listener(mgr, &addr, allow, block).await {
            eprintln!("[server] agent listener error: {}", e);
        }
    });

    // Start HTTP proxy if port is configured
    if cli.http_proxy_port > 0 {
        let mgr = manager.clone();
        let domain = cli.http_proxy_domain.clone();
        tokio::spawn(async move {
            if let Err(e) =
                agent_manager::start_http_proxy(mgr, cli.http_proxy_port, &domain).await
            {
                eprintln!("[server] HTTP proxy error: {}", e);
            }
        });
    }

    let web_addr = cli.web_addr.clone();
    println!("[server] agent protocol on {}", cli.agent_addr);
    println!("[server] web UI on      http://{}", web_addr);
    if cli.http_proxy_port > 0 {
        println!(
            "[server] HTTP proxy on    port {} (domain: {})",
            cli.http_proxy_port,
            if cli.http_proxy_domain.is_empty() {
                "(any)"
            } else {
                &cli.http_proxy_domain
            }
        );
    }
    if !cli.allow_tokens.is_empty() {
        println!("[server] allow tokens: {}", cli.allow_tokens);
    }
    if !cli.block_tokens.is_empty() {
        println!("[server] block tokens: {}", cli.block_tokens);
    }
    if !cli.password.is_empty() {
        println!("[server] web password:  {} (login required)", cli.password);
    }

    web::run(manager, &web_addr, &cli.password).await?;
    Ok(())
}