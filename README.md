# Abyss

一个轻量级的远程路由器管理系统，由 **Agent（客户端）** 和 **Server（服务端）** 两部分组成。

Agent 运行在 OpenWrt / LEDE / 其他嵌入式 Linux 路由器上，主动连接 Server，Server 通过 Web UI 或 API 下发指令，实现远程 Shell 执行、端口映射、Web 反向代理等功能。

---

## ✨ 特性

- 🖥️ **远程 Shell 执行** — 在路由器上执行任意命令，实时返回输出
- 🔀 **端口映射** — 将路由器本地端口（如 SSH / Web）穿透到公网服务器
- 🌐 **Web 反向代理** — 通过域名自动路由到不同路由器的 Web 管理界面
- 🔐 **XOR 流加密** — 所有 Agent ↔ Server 通信可选 XOR 加密，防止中间人
- 🔑 **Token 分组管理** — 多租户隔离，支持白名单 / 黑名单
- 🛡️ **IP 自动封禁** — 检测到异常握手（如扫描、暴力尝试）自动封禁 IP
- 🌍 **IP 归属地** — 集成纯真 IP 库（qqwry.dat）显示 Agent 来源地理位置
- 🔄 **断线自动重连** — Agent 端无限重试，连接断开立即恢复
- 💓 **多层心跳保活** — TCP Keepalive + 30 分钟应用层心跳，及时发现死连接
- 📶 **自定义 DNS 解析** — Agent 内置零依赖 DNS 客户端，可指定自定义 DNS 服务器
- 🕵️ **进程参数隐藏** — 在 Linux 上覆盖 `/proc/self/cmdline`，隐藏 Agent 进程
- 🔨 **静态交叉编译** — 支持 x86_64 / aarch64 / mips / mipsel / armv7，全部静态链接 musl

---

## 🏗️ 架构

```
┌──────────────┐      TCP (XOR 可选加密)      ┌──────────────────┐
│   路由器 A    │  ──── abyss Agent ────▶     │                  │
│  (OpenWrt)   │                              │                  │
└──────────────┘                              │                  │
                                              │  abyss-server    │
┌──────────────┐      TCP (XOR 可选加密)      │                  │
│   路由器 B    │  ──── abyss Agent ────▶     │  - Agent 管理     │
│  (OpenWrt)   │                              │  - Shell 执行     │
└──────────────┘                              │  - 端口映射       │
                                              │  - HTTP 代理      │
                                    ┌────────▶│                  │
                                    │         │                  │
                              Web  │         │                  │
                              UI   │         └──────────────────┘
                                    │
                            浏览器 / API 调用
```

协议是简单的基于行的文本协议（带长度前缀的二进制帧），支持以下命令：

| 方向 | 命令 | 说明 |
|------|------|------|
| Agent → Server | `HELLO name [id] token [flash_time]` | 握手注册 |
| Server → Agent | `EXEC op_id command` | 远程执行命令 |
| Agent → Server | `EXEC_RESULT op_id code` + 输出 + `.END` | 命令执行结果 |
| Server → Agent | `TUN_OPEN tunnel_id local_addr` | 请求建立隧道 |
| Agent → Server | `TUN_OK / TUN_CLOSE tunnel_id` | 隧道就绪 / 失败 |
| 双向 | `TUN_DATA tunnel_id len\n<bytes>` | 隧道数据帧 |
| 双向 | `TUN_CLOSE tunnel_id` | 关闭隧道 |
| 双向 | `PING / PONG` | 心跳保活 |

---

## 📦 快速开始

### 构建

需要 Rust 1.70+。

```bash
# 构建全部
cargo build --release

# 仅构建 Agent
cargo build --release -p abyss

# 仅构建 Server
cargo build --release -p abyss-server
```

### 交叉编译（Agent）

项目已内置 musl 交叉编译配置。在 GitHub Actions 上会自动构建以下目标：

| 二进制 | 目标平台 |
|--------|----------|
| `abyss` | `mips-unknown-linux-musl` （常见 OpenWrt MIPS 路由器） |
| `abyss` | `mipsel-unknown-linux-musl` （MIPS 小端路由器） |
| `abyss` | `armv7-unknown-linux-musleabihf` （ARMv7 路由器） |
| `abyss` | `x86_64-unknown-linux-musl` |
| `abyss` | `aarch64-unknown-linux-gnu` |
| `abyss-server` | `x86_64-unknown-linux-musl` |
| `abyss-server` | `aarch64-unknown-linux-gnu` |

---

## 🚀 运行

### Server 端

```bash
# 最简单启动（无密码，接收所有 token）
./abyss-server

# 完整参数
./abyss-server \
  --agent-addr 0.0.0.0:46293 \
  --web-addr 0.0.0.0:33671 \
  --http-proxy-port 18080 \
  --password "your_admin_password" \
  --allow-tokens "group_a,group_b" \
  --block-tokens "blocked_group" \
  --crypto-key "your_secret_key" \
  --crypto-key-no
```

**参数说明：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--agent-addr` | `0.0.0.0:46293` | Agent 协议监听地址 |
| `--web-addr` | `0.0.0.0:33671` | Web UI / API 监听地址 |
| `--http-proxy-port` | `18080` | HTTP 反向代理端口（0 表示禁用） |
| `--password` | *(空)* | Web UI 管理密码。为空则不需要登录 |
| `--allow-tokens` | *(空)* | Token 白名单，逗号分隔。为空则允许所有 |
| `--block-tokens` | *(空)* | Token 黑名单，逗号分隔 |
| `--crypto-key` | `Zzb33cANnGVGdQWe` | Agent 通信 XOR 加密密钥 |
| `--crypto-key-no` | `false` | 禁用 XOR 加密（明文模式） |

启动后控制台会输出：

```
[server] agent protocol on 0.0.0.0:46293
[server] web UI on      http://0.0.0.0:33671
[server] HTTP proxy on    port 18080 (domain: dome.com)
```

#### IP 归属地查询（可选）

将纯真 IP 库 `qqwry.dat` 放入 Server 工作目录下的 `data/` 子目录：

```
./abyss-server
./data/
└── qqwry.dat
```

未找到时 Server 会输出提示，IP 查询功能自动禁用，不影响其他功能。

#### HTTP 反向代理

如果你配置了域名（如 `dome.com`），并让 DNS 将 `*.dome.com` 指向 Server 的 IP，即可通过子域名直接访问路由器的 Web 界面：

```
┌─────────────────┐    Host: router1.dome.com:18080    ┌─────────────┐
│  用户浏览器       │ ──────────────────────────────▶  │  abyss-server │
└─────────────────┘                                    └──────┬──────┘
                                                               │ TUN 隧道
                                                               ▼
                                                    ┌──────────────┐
                                                    │  abyss Agent │
                                                    │  127.0.0.1:80 │
                                                    └──────────────┘
```

首次使用需在 Web UI 中点击「Web快速访问 → 启用」选中目标 Agent，之后访问格式为：

```
http://<agent_id>.yourdomain.com:18080
```

---

### Agent 端

```bash
# 最简启动
./abyss -s server.example.com:46293 -t my_group

# 完整参数
./abyss \
  --server server.example.com:46293 \
  --token my_group \
  --name my_router \
  --id aa:bb:cc:dd:ee:ff \
  --crypto-key "your_secret_key" \
  --dns 223.5.5.5 \
  --flash-time 1700000000
```

**参数说明：**

| 参数 | 缩写 | 默认值 | 说明 |
|------|------|--------|------|
| `--server` | `-s` | `dome.y-lin.wang:46293` | Server 地址 |
| `--token` | `-t` | `unauthorized` | 分组 Token |
| `--name` | `-n` | OpenWrt 自动读取 `productid` | 显示名称 |
| `--id` | `-i` | OpenWrt 自动读取 MAC 地址 | 唯一标识 |
| `--crypto-key` | `-k` | `Zzb33cANnGVGdQWe` | 与 Server 一致的 XOR 密钥 |
| `--crypto-key-no` | — | `false` | 禁用 XOR 加密 |
| `--dns` | `-d` | `223.5.5.5` | 自定义 DNS 服务器（内置解析器） |
| `--flash-time` | — | *(空)* | 刷机时间戳（Unix，可选） |

#### OpenWrt 上自动参数

在 OpenWrt / LEDE 路由器上运行时，Agent 会自动：
- 通过 `nvram get productid` 获取设备型号作为 **name**
- 通过 `lan_eeprom_mac` 获取 MAC 地址作为 **id**
- 启动后覆盖 `/proc/self/cmdline`，将进程名伪装为 `abyssd`

#### 设为开机自启

```bash
# OpenWrt /etc/init.d/abyss
cat > /etc/init.d/abyss << 'EOF'
#!/bin/sh /etc/rc.common
START=99
PROG="/path/to/abyss"
ARGS="-s server.example.com:46293 -t my_group"

start_service() {
  procd_open_instance
  procd_set_param command $PROG $ARGS
  procd_set_param respawn
  procd_close_instance
}
EOF

chmod +x /etc/init.d/abyss
/etc/init.d/abyss enable
/etc/init.d/abyss start
```

---

## 🌐 Web UI

浏览器打开 Server 的 Web 端口（默认 `http://server_ip:33671`），功能包括：

- **设备列表** — 查看所有在线 / 离线 Agent，支持搜索和 Token 分组过滤
- **设备详情** — 查看 Agent IP、归属地、上线时间、在线时长、刷机时间等
- **Shell 执行** — 在选中的 Agent 上执行命令
- **端口映射** — 创建 / 管理端口穿透
- **Web 快速访问** — 一键启用 HTTP 反向代理
- **连接检测** — 发送 PING 验证 Agent 存活

---

## 📡 HTTP API

所有接口需要携带 Cookie（`token=xxx`）或 Header（`Authorization: Bearer xxx`）进行认证。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/login` | 登录获取 Session Token |
| GET | `/api/agents?q=xxx` | 获取 Agent 列表 |
| POST | `/api/exec` | 执行远程命令 |
| POST | `/api/ping` | 检测 Agent 存活 |
| POST | `/api/forward` | 创建端口映射 |
| POST | `/api/forward/stop` | 停止端口映射 |
| GET | `/api/forwards` | 列出所有映射 |
| GET / POST | `/api/config` | 获取 / 设置域名配置 |
| POST | `/api/web/select` | 选择 HTTP 代理目标 Agent |

---

## 🛡️ 安全建议

1. **修改默认 crypto-key** — XOR 不是强加密，但可以有效防止被动嗅探和协议识别，务必修改默认密钥
2. **设置 Web 密码** — 通过 `--password` 参数启用登录
3. **使用 Token 隔离** — 为不同的 Agent 组使用不同的 Token
4. **使用 allow-tokens** — 只允许已知的 Token 连接，拒绝陌生 Agent
5. **Server 绑定内网** — 如果不需要公网访问 Web UI，可以只监听 `127.0.0.1`

---

## 📁 项目结构

```
abyss/
├── Cargo.toml              # Workspace 根配置
├── Cross.toml              # Cross 交叉编译配置
├── .cargo/config.toml      # Rustflags
├── .github/workflows/build.yml
│
├── agent/                  # Agent 客户端
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # 主逻辑：连接、会话、隧道管理
│       ├── crypto.rs       # XOR 加密
│       └── dns.rs          # 零依赖 DNS 解析器
│
└── server/                 # Server 服务端
    ├── Cargo.toml
    └── src/
        ├── main.rs         # 入口、CLI 参数
        ├── agent_manager.rs # Agent 管理、协议处理、隧道、端口映射、HTTP 代理
        ├── web.rs          # Web UI 后端、路由
        ├── ip_lookup.rs    # 纯真 IP 库查询
        ├── crypto.rs       # XOR 加密
        └── static/
            └── index.html   # Web UI 前端
```

---

## 🧩 依赖

### Agent（零第三方 crate）
Agent 端**不使用任何第三方依赖**，全部依赖 Rust 标准库：
- `std::net` — TCP 连接、UDP DNS
- `std::process` — Shell 命令执行
- `std::sync` — 多线程同步
- `std::thread` — 隧道管理线程
- `libc` — (Linux) socket 选项

### Server
| Crate | 用途 |
|-------|------|
| `tokio` | 异步运行时 |
| `axum` | Web 框架 |
| `serde` / `serde_json` | JSON 序列化 |
| `clap` | CLI 参数解析 |
| `anyhow` | 错误处理 |
| `socket2` | TCP Keepalive、SO_REUSEADDR |
| `qqwry` | 纯真 IP 库查询 |

---

## 📄 License

MIT