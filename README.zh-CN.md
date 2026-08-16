# poolgate（中文说明）

> Codex / ChatGPT 账号池网关：把一组 Codex 账号聚合成一个 OpenAI 兼容的本地端点，
> 按策略路由、自动容错、主动健康探测，并带完整的运维 / 灾备 / 安全能力。
> 英文文档见 [`README.md`](README.md)；权威设计见 [`docs/DESIGN.md`](docs/DESIGN.md)。

poolgate 是一个**单文件、纯 Go、无 CGO** 的服务：把多个 Codex/ChatGPT 凭据放进一个池子，
对外暴露一个 OpenAI 兼容的 `/v1/responses` 端点。它是一个**翻译网关**（不是透明反向代理）——
入站用你自己的 `sk-` 密钥鉴权，出站把 `Authorization` 与 `ChatGPT-Account-ID` 一起改写成所选池内账号，
强制流式，并把上游固定为 `chatgpt.com`。

---

## 1. 已完成功能总览

### 路由与策略
- **四种路由策略**：
  - `fallback` — 按顺序取第一个健康账号，失败则顺延并冷却。
  - `best-quota` — 路由到剩余额度（各用量窗口 `100 − used_percent` 的最小值）最高的账号，低位 id 决定平局。
  - `load-balance` — 健康账号间**最少在途优先**的轮询（并发未跟踪时退化为普通轮询）。
  - `weighted` — **加权负载均衡**（平滑加权轮询 SWRR，PR #52）：每个成员按权重（≥1）成比例分流。
- **严格“首字节前”容错**：上游在任何字节写回客户端之前出错时才重选下一个账号；一旦开始流式即提交、不再切换。
- **被动健康钩子**：401 → 单飞刷新令牌后重试同账号；429 → 依据 `Retry-After` 冷却；5xx → 保守冷却。
- **主动健康探测引擎**：按账号状态分级探测（零 token 花费的用量轮询 / auth-check，可选小额 live 探测），
  额度/限速恢复后**自动恢复**账号。
- **并发上限 + 有界队列背压**：每账号并发上限；所有健康成员都打满时，短暂等待空位，否则返回 429 + `Retry-After`。

### 传输层
- **HTTP POST + SSE**（默认路径）：逐块 flush 的流式转发。
- **WebSocket 代理 + 会话粘滞**（PR #46）：接受 Codex 的 WS `/responses` 升级并透明转发到所选上游账号；
  连接级账号粘滞（一次会话固定一个后端 = turn affinity），另支持 `x-codex-turn-state` 升级头做跨重连粘滞（短 TTL）；
  升级前容错、心跳保活（防止死连接占用并发槽）。
- **传输可配置**（PR #50）：`server.transport` / `POOLGATE_PROXY_TRANSPORT` = `both`（默认）| `http-only`（拒绝 WS，回落 HTTP）| `ws-only`（拒绝普通 POST，返回 426）。**两种传输都不是强制的**。

### 管理后台（Admin API + Web UI）
- **Passkey / WebAuthn 登录**：首个 passkey 由一次性 bootstrap token 引导，之后凭会话注册更多 passkey，支持一次性恢复码与跨设备（扫码）登录；`admin reset-auth` 为本地锁定逃生通道。
- **会话 + CSRF + 严格安全头/CSP**，同源限制；所有管理路由需 passkey 会话。
- **资源管理**：账号导入/列表/删除、**编辑账号并发上限与标签**（PR #48）、策略组增删改（含权重）、端点、`sk-` 代理密钥。
- **代理密钥生命周期**（PR #31 + UI）：过期时间、IP 白名单（匹配直连对端）、轮换（rotate）。
- **实时监控**：请求日志 SSE 实时流 + 头部计数器 + 可组合过滤。
- **通知**：DingTalk / 企业微信 / 自定义 webhook 渠道，SSRF 防护出站；账号状态变化、额度低、无健康成员，以及 **`auth_anomaly`（凭据探测）/ `startup_bind_warning`（非回环绑定）事件**（PR #49）。
- **客户端配置生成器**：为选定端点生成 `OPENAI_BASE_URL`/`OPENAI_API_KEY` + curl 片段（PR #44）。

### 交互式登录
- **`poolgate login`**（PR #41）：OAuth 授权码 + **PKCE**（S256、单次性 `state`、回环回调 `127.0.0.1:1455`）浏览器登录添加账号，无需粘贴 `auth.json`；从 id_token 的 `chatgpt_account_id` claim 取账号 id。

### 存储与加密
- **纯 Go SQLite**（modernc，无 CGO）+ **字段级加密**：账号 access/refresh 令牌、通知渠道密钥用 NaCl secretbox（XSalsa20-Poly1305）加密后入库。
- **WAL 模式**、单连接串行化、原子迁移；**Schema 降级保护 + 迁移前快照**（PR #26）。

### 运维、灾备与安全（Ops/DR）
- **备份 / 恢复**（PR #20）：passphrase 包裹（argon2id + secretbox）的可移植捆绑包，含主密钥 + 一致性 `VACUUM INTO` 快照；恢复原子、拒绝覆盖活库、KDF 参数上限防 DoS。
- **单实例锁**（PR #22）：`flock` 保证同一数据目录只有一个 `serve`。
- **优雅下线**（PR #24）：admin 监控 SSE 及时 drain，代理保留完整 Shutdown 宽限期完成有限响应。
- **`<NAME>_FILE` 密钥约定**（PR #29）：`POOLGATE_MASTER_KEY` / `POOLGATE_BACKUP_PASSPHRASE` 支持 Docker/K8s secret 文件。
- **内存卫生**（PR #37）：`serve` 启动即禁用 core dump（`RLIMIT_CORE=0`）并尽力 `mlockall` 防止密钥换页，失败仅告警。
- **时钟对齐**（PR #39）：用量窗口锚定上游 `reset_at`；从 `reset_at − reset_after_seconds` 测得 host↔上游**时钟偏移**，越阈告警并在 `GET /admin/api/status` 暴露。
- **防篡改审计日志**（PR #33 + #53）：仅追加、无更新/删除；每条记录以 `SHA256(prevHash ‖ 字段)` **哈希链**串联，`GET /admin/api/audit/verify` 校验（可检出偶发损坏与中段篡改/删除/乱序；无法检出尾部截断或能重算链尾的 DB 写入者）。
- **主密钥轮换**（PR #54）：`poolgate rotate-key` 生成新主密钥并在**单事务内**批量重新加密全部密文列，先写轮换前快照，持锁执行，再原子替换 keyfile（或对 env 源打印新密钥）。
- **部署配方**（PR #35）：`deploy/` 提供 docker-compose + Caddy/nginx 反代（TLS、SSE 不缓冲、只读根文件系统、`mlock` ulimit），见 [`docs/DEPLOY.md`](docs/DEPLOY.md)。

### 发布与 CI
- CI：build/vet/staticcheck 2026.1/`-race` 测试/**每包覆盖率 ≥80%**/域名仿冒 lint/govulncheck。
- 发布：GoReleaser 跨平台归档 + `SHA256SUMS` + cosign（keyless OIDC）签名 + 多架构 distroless 镜像 + Homebrew tap（SHA 固定的 GitHub Actions）。

---

## 2. 快速开始

```sh
# 从源码构建（纯 Go，无需 npm）
go build -o ./poolgate ./cmd/poolgate

./poolgate init                    # 初始化数据目录 + 主密钥 + 迁移，打印一次性 bootstrap token
./poolgate import ~/.codex/auth.json   # 或者：./poolgate login（浏览器 OAuth+PKCE）
./poolgate serve                   # 同时启动代理(:8787)与 admin(:7070) 两个监听 + 健康调度
```

容器部署与反向代理见 [`docs/DEPLOY.md`](docs/DEPLOY.md)；完整运行指南见 [`docs/RUN.md`](docs/RUN.md)。

---

## 3. 运行时资源需求评估

poolgate 是单个静态二进制，资源占用很低，适合小规格 VPS / 容器 / 树莓派级设备。

| 维度 | 需求 | 说明 |
|------|------|------|
| **二进制体积** | ~15 MB（`-s -w` 精简后；未精简约 20 MB） | 纯 Go 静态、无 CGO；已内嵌 React 管理界面（go:embed） |
| **空闲内存 (RSS)** | **约 22 MB**（实测 `serve` 空闲） | Go 运行时 + 单连接 SQLite + 两个 HTTP 监听 + 健康调度 goroutine |
| **负载内存** | 每个在途请求/SSE 流约几十 KB～数 MB 缓冲；由每账号并发上限约束 | 单条消息读上限 32 MiB（HTTP body 与 WS 帧）；WS 每连接占一个并发槽 |
| **CPU** | 以 I/O 为主（转发/流式中继），基本空闲 | secretbox 每次令牌读写为微秒级；argon2id 仅在 backup/restore 时发生（内存/时间参数有上限）；健康探测按分钟级 cadence |
| **磁盘** | 数据库通常 < 数十 MB | 账号/密钥/端点很小；`request_logs` 会定期裁剪；另有 `master.key`、可选备份与轮换前快照（保留最近 3 份） |
| **网络** | 出站仅到 `chatgpt.com` / `api.openai.com`（白名单固定） | 长连接 SSE / WS；反代需关闭缓冲、放宽读超时 |
| **文件句柄** | 少量 | SQLite 单连接（`SetMaxOpenConns(1)`）+ 每活跃客户端/上游连接 |
| **最低规格建议** | **1 vCPU / 128 MB 内存** 足够轻量使用 | 内存主要随并发在途请求数与 WS 连接数线性增长；给缓冲留冗余建议 256 MB |

要点：
- **无外部依赖**：不需要单独的数据库/Redis/消息队列——SQLite 文件即全部状态。
- **无常驻高 CPU**：没有轮询式忙等；健康调度是定时器驱动。
- **内存卫生**：`serve` 会禁用 core dump 并尽力 `mlock`（容器里需放宽 `memlock` ulimit 才能真正生效，否则仅告警）。
- **容器**：distroless/nonroot 镜像，可开启只读根文件系统（仅 `/data` 卷与 `/tmp` tmpfs 可写）。

---

## 4. 文档索引

- [`README.md`](README.md) — 英文总览
- [`docs/DESIGN.md`](docs/DESIGN.md) — 架构、策略引擎、存储、鉴权、配置（权威）
- [`docs/RUN.md`](docs/RUN.md) — 本地运行、登录、密钥轮换、传输模式、配置项
- [`docs/DEPLOY.md`](docs/DEPLOY.md) — Docker Compose + Caddy/nginx 反代部署
- [`docs/SECURITY.md`](docs/SECURITY.md) — 威胁模型与加固矩阵
- [`docs/BUILD.md`](docs/BUILD.md) — 发布与打包
