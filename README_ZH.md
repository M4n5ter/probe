# Probe

[English](README.md) · [设计文档](docs/design.md) ·
[Lua policy](docs/lua-policy_ZH.md) ·
[Webhook receiver](docs/webhook-receiver_ZH.md) ·
[HTTP endpoints](docs/http-endpoints_ZH.md) ·
[安全默认配置](examples/agent.toml) · [本地演示配置](examples/local-agent.toml)

Probe 是一个 Linux 进程级网络流量探针，用于安全遥测、协议可见性、证据持久化、外发和受控防护。

它在主机上观测流量，将流量关联到进程和 socket，解析协议语义，执行 Lua policy，写入 durable
event evidence，并导出结构化 batch。它面向无法依赖旁路镜像、专用硬件、service-mesh sidecar
或业务 SDK 的服务器环境。

Probe 现在已经可以在受控 Linux 环境中正常试用和集成。它还不是一键式生产 appliance：
privileged live capture、transparent interception 和 MITM 都需要明确的主机配置、operator
管理的信任决策和 capability check。

## 当前能做什么

- 无 root 体验完整 parser/policy/spool/export 闭环：
  使用 `examples/local-agent.toml`，通过 plaintext feed 和 file exporter 跑本地 demo。
- 重新处理已捕获字节流：
  使用 `agent replay`，输入 raw HTTP 文件，可选 Lua policy。
- 接入确定性的外部输入：
  使用 `capture.selection = "plaintext_feed"` 或
  `capture.selection = "capture_event_feed"`。
- 采集 live traffic：
  libpcap 需要 root/CAP_NET_RAW；eBPF 需要 object path 和主机前置条件。
- 观察 TLS 流量：
  使用 key log/session-secret material、libssl uprobe plaintext
  instrumentation、显式 plaintext bridge 或 scoped MITM。
- 导出事件：
  使用 webhook、Unix HTTP sidecar 或 file sink，并选择 `none`、`zstd`、`gzip`、`deflate` 压缩。
- 执行策略：
  使用本地或远程 Lua policy bundle 处理 typed event 和 verdict。
- 保护选定应用：
  使用 audit-only、dry-run、scoped TCP connection destroy、transparent
  interception 或 MITM policy hook。

capability model 是显式契约。provider 不可用或证据降级时，`agent capabilities`、`agent check`
和 `agent status` 会直接报告，而不是把 best-effort observation 伪装成完整观测。

## 快速开始

Debian 或 Ubuntu 主机上，先安装默认 build 需要的原生依赖：

```bash
sudo apt-get install -y libpcap-dev pkg-config
```

安装默认 agent build 会用到的 eBPF build toolchain：

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

构建主 binary：

```bash
cargo build -p agent -p xtask --locked
```

查看当前主机能力：

```bash
cargo run -p agent --locked -- capabilities
```

运行非特权本地 demo：

```bash
rm -rf target/probe-demo
mkdir -p target/probe-demo

cargo run -p agent --locked -- check --config examples/local-agent.toml
cargo run -p agent --locked -- run --config examples/local-agent.toml --max-events 3
wc -l target/probe-demo/export.jsonl
head -n 1 target/probe-demo/export.jsonl
```

这条路径会读取 [examples/plaintext-feed.jsonl](examples/plaintext-feed.jsonl)，加载
[examples/policies/http-alert](examples/policies/http-alert)，把事件写入
`target/probe-demo/spool`，并向 `target/probe-demo/export.jsonl` 追加一个 file-export batch。

file exporter 写出的是 JSON Lines batch record。每一行包含 metadata，以及 base64 编码的
protobuf batch envelope；payload 是否压缩由 codec 决定。它面向 collector 和后续工具消费，
不是漂亮的人类可读事件日志。

在不需要 live-capture 权限的情况下 replay raw HTTP bytes：

```bash
rm -rf target/probe-demo/replay-spool

cargo run -p agent --locked -- replay \
  --input examples/replay.http \
  --spool target/probe-demo/replay-spool \
  --policy examples/policies/http-alert/main.lua \
  --agent-id probe-replay-demo
```

运行不需要特权的单机验证路径：

```bash
cargo run -p xtask --locked -- validate-local
```

运行非特权 E2E baseline：

```bash
cargo run -p xtask --locked -- e2e-suite --profile baseline
```

真实 collector 或 policy rollout 从 [最小 Policy 与 Webhook 接线](#最小-policy-与-webhook-接线) 开始。

## 安装要求

通用要求：

- Linux 和 procfs；
- 支持 edition 2024 的 stable Rust；
- 默认 agent build 需要 `libpcap` development headers 和 `pkg-config`；
- live capture、eBPF、socket destroy、transparent interception 或 MITM 测试需要 root 或对应 Linux capability；
- 运行 Linux transparent interception 时需要 `nftables` package；
- 需要带 `rust-src` 的 nightly Rust 和 `bpf-linker`；agent build 默认会嵌入
  first-party process-observation 和 TLS uprobe object。

常见 `nft` 安装命令：

```bash
# Debian / Ubuntu
sudo apt install nftables

# Fedora / RHEL / Rocky / Alma
sudo dnf install nftables

# Arch
sudo pacman -S nftables

# Alpine
sudo apk add nftables
```

`nft` 缺失时，agent capability probe 会先读取 `/etc/os-release`，未知发行版再探测常见
package manager。probe 自身已经以 root 运行时，报告的安装命令不会带 `sudo`。

运行 MITM E2E 时构建 first-party MITM proxy 和 fixture：

```bash
cargo build -p agent -p e2e-fixture -p mitm-proxy -p xtask --locked
```

开发或验证自定义 eBPF object 时构建 eBPF artifact：

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo run -p xtask --locked -- ebpf-build
```

agent build 默认会嵌入 first-party process-observation 和 TLS uprobe object。
运行时会把需要的内置 object 物化到 `PROBE_HOME/artifacts/ebpf`。只有使用自定义或外部管理的
eBPF object 时，才设置 `capture.ebpf.object_path` 或
`tls.plaintext.instrumentation.libssl_uprobe_object_path`。

## 选择运行模式

- `agent replay`：
  将单个 raw byte stream 经过 parser、policy、spool 和可选 webhook export；
  不需要 live-capture 权限。
- `plaintext_feed`：
  使用可读 JSONL 做开发、SDK、测试、bridge 或可信 plaintext handoff。
- `capture_event_feed`：
  接收 MITM bridge 或外部采集器输出的 typed `CaptureEvent` JSONL；
  `follow = true` 可以让 agent 保持在线。
- `libpcap`：
  eBPF 不可用或未配置时的 live packet capture；通过 procfs socket attribution
  补充 process context，可在可用时覆盖 container network namespace 和
  docker-proxy published-port logical ownership；需要 root 或 CAP_NET_RAW。
- `ebpf`：
  kernel-assisted process-aware observation；需要 root/bpffs 和已构建 eBPF object。
  深度观测受 selector gate 约束；syscall payload bytes 是 degraded evidence，
  当前内核暴露的 `sendfile(2)`/`sendfile64(2)` tracepoint variant 输出
  byte-count gap，不输出 payload bytes。runtime status 会报告当前内核暴露了哪些
  optional syscall variant。
- libssl uprobe：
  针对选定 libssl 进程的 best-effort TLS plaintext sidecar；需要
  root/bpffs、内嵌或显式配置的 TLS uprobe object，以及显式 selector。
- Transparent interception：
  对 scoped inbound/outbound traffic 做 steering；需要 root/net-admin 和显式 selector。
- Product MITM proxy：
  scoped TLS termination、upstream relay、plaintext bridge 和 proxy-side policy hook；
  需要 root/net-admin、certificate material 和 operator-managed client trust。

## 配置 Probe

从以下文件开始：

- [examples/local-agent.toml](examples/local-agent.toml)：可直接运行的本地 demo；
- [examples/agent.toml](examples/agent.toml)：带注释的安全默认服务器模板。

运行前校验配置：

```bash
cargo run -p agent --locked -- check --config ./agent.toml
cargo run -p agent --locked -- status --config ./agent.toml
```

`check` 会校验 runtime plan 和配置的 policy。`status` 是副作用较轻的状态快照；
它会报告本地 policy bundle 的 metadata，但不会执行 policy source。

### 服务器本地 TUI

直接在 Linux 主机上运维时可以使用 TUI：

```bash
cargo run -p agent --locked -- tui
```

TUI 是面向常见服务器操作的配置工作台。它通过 agent 共用的 procfs attribution
模型读取 `/proc`，展示可读进程。键盘和鼠标是同级交互方式：常见 action 只建模
一次，并同时通过 key binding 和 rendered hit target 暴露。只有进程具备可读
executable path 时才会写入 process scope；进程表默认只展示隐藏后的 argv count，
TUI model 不保留 raw argv。保存会获取 advisory lock，拒绝已被外部修改的配置文件，
校验渲染后的配置，并使用同目录原子写入。配置路径必须是 direct file path；
symlink path 会被拒绝，避免保存时把链接替换成普通文件。

工作台可添加默认 exporter、切换 exporter transport、编辑 webhook endpoint、
file path、Unix HTTP socket path、exporter compression、export worker state、
storage retention record limits、capture backend selection、enforcement mode/backend、
transparent interception strategy、TLS plaintext hook enablement，以及 capture、
enforcement、interception、TLS plaintext 的进程级 selector。Policy Lua source、
大型 MITM backend contract、TLS material 文件、exporter header/TLS material ref 和
collector-specific payload format 仍应在配置和 policy 文件中维护。

不传 `--config` 时，TUI 使用 `PROBE_HOME/config/agent.toml`；文件不存在会创建一份最小安全配置。
需要编辑指定文件时可以传 `--config ./agent.toml`。

当配置中的 admin socket 已启用且 live agent 正在运行时，Traffic tab 会通过在线
admin surface tail 已解析的 export event。它优先使用选中进程的 executable-path
selector；如果选中进程没有可读 executable path，流量过滤会 fail closed，不会退回展示无关的全机流量。
TUI 的事件表只保留展示摘要，不保留进程 raw argv。bounded tail row 需要完整 payload
详情时，详情弹窗会通过 admin surface 在后台加载仍被保留的事件。
Traffic 可以按 HTTP exchange、WebSocket session 或 raw event 三种视图查看。
HTTP 视图会把 request headers、request body chunks、response headers 和 response body chunks
组织成同一条 exchange。WebSocket 视图会把 Upgrade handoff、frame metadata 和有界 message
payload 组织成同一条 session。raw event 视图用于查看 SSE event、connection lifecycle、
parser gap 或 capture provider diagnostics。
同一 Traffic tab 也提供 `Watch`、`Out MITM` 和 `In MITM` 操作，选中进程后即可配置
passive traffic scope 或 product-proxy MITM，不需要切换到单独的配置页面。出站 MITM
quick action 默认使用 80 和 443 端口，让普通明文 HTTP 和 TLS 解密后 HTTP 进入同一条
plaintext bridge 与 traffic view。

Runtime tab 可以调用在线 admin `reload_runtime_actions` 命令，重载 active `RuntimePlan`
中明确可在线切换的 runtime owner，目前包括 policy bundles 和 enforcement policy source，
并逐个 action 报告成功或失败。TUI 保存配置时，如果有 active admin socket，会先调用
`apply_config_reload`：policy-only 主配置变更在 policy watcher/poller topology 不变且未启用时
在线应用；enforcement policy source 和 `enforcement.selector` 变更在 enforcement reload watcher/poller topology
未启用且 transparent interception 未持有 setup-time host rules 时在线应用。顶层 `[selectors]`
registry 变更，包括被 `enforcement.selector` 引用的条目变更，仍需要重启，直到 selector ownership
具备独立 lifecycle owner。capture、observation、config version、TLS plaintext instrumentation 和 TLS
decrypt-hint material rebuild verdict 会排入 runtime generation request，并由 live agent 在 capture safe
point 交换。queued response 会携带 generation request id；TUI 会跟踪 status，直到该 request applied、failed，
或超过后台等待窗口后仍 pending。在线 apply 失败、已入队 generation failed 或仍 pending 时，旧
running agent 继续保留，TUI 在状态行报告结果。generation request 无法入队时，TUI-managed agent
可以重启以收敛到保存配置；attached external agent 会提示显式重启或重试。export、storage、admin
socket、watcher topology 等 setup-time topology 仍需要进程 rebuild。

### 最小 Policy 与 Webhook 接线

第一次接入真实系统时先看这一节。可部署配置需要显式描述四份契约：event 从哪里来、durable
state 存在哪里、哪些 Lua hook 检查 typed event、collector 如何确认 export batch。Probe
不会从 endpoint 名称或 policy 文件名推断这些契约。

`PROBE_HOME` 是 config default 和 TUI-generated path 使用的本地状态根目录。
默认遵循用户 state 目录：优先使用 `$XDG_STATE_HOME/traffic-probe`；未设置
`XDG_STATE_HOME` 时使用 `$HOME/.local/state/traffic-probe`。如果状态目录需要放到其它位置，
应在创建或编辑配置前显式设置：

```bash
export PROBE_HOME="/var/lib/traffic-probe"
```

TOML 中显式写出的 path 会按字面值使用，不做环境变量展开。受限环境里没有可用用户 home 时，
Probe 会退回 `/var/lib/traffic-probe`。

卸载 Probe 应当足够直接：先停止正在运行的 service，再按安装方式删除 binary 或 package，最后删除
Probe 生成的本地状态树：

```bash
# 默认用户级状态。
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/traffic-probe"

# PROBE_HOME 设为机器级服务状态目录时。
sudo rm -rf /var/lib/traffic-probe
```

如果部署使用了自定义 `PROBE_HOME`，删除那个目录即可。外部 config、policy、certificate 和
systemd unit path 归 operator 所有，应按部署自己的安装布局清理。

```text
/etc/probe/agent.toml
/etc/probe/policies/http-guard/manifest.toml
/etc/probe/policies/http-guard/main.lua
```

先使用确定性输入和未压缩 webhook 做 interop。receiver 通过后，再把
`capture.selection` 切到 live backend，并把 `codec = "zstd"` 或其它支持的 codec 打开。

agent config：

```toml
[capture]
selection = "plaintext_feed"

[capture.plaintext_feed]
path = "/var/lib/traffic-probe/plaintext-feed.jsonl"

[storage]
path = "/var/lib/traffic-probe/spool"

[export.worker]
enabled = true

[[exporters]]
id = "primary-webhook"
transport = "webhook"
endpoint = "https://collector.example/probe/batches"
codec = "none"
headers = { x_probe_node = "edge-a" }

[[policies]]
id = "http-guard"
enabled = true
runtime_error_disable_threshold = 3

[policies.source]
kind = "local_directory"
path = "/etc/probe/policies/http-guard"

[enforcement]
mode = "audit_only"
backend = "none"
```

policy manifest：

```toml
id = "http-guard"
version = "2026-06-30"
hooks = ["on_http_request_headers", "on_websocket_message"]
```

Lua policy 写法：

- `agent run` 加载 policy bundle 目录，而不是单个 Lua 文件。
- `manifest.toml` 声明 Probe 可以调用哪些 hook；每个 hook 都必须在
  `main.lua` 中实现为同名全局 Lua 函数。
- 每个 hook 接收一个 typed `event` table。通用 metadata 在 `event` 上，
  协议字段在 `event.kind` 上。
- 64 KiB 以内的 WebSocket text message 暴露 `event.kind.payload_text`；
  更大的 text message 和 binary message 暴露 length 与 fingerprint，
  不会把 payload bytes 展开成 Lua table。
- hook 可以返回 `nil`、一个 outcome，或 outcome 数组。
- `probe.emit_alert(message)` 产生审计 telemetry。
- `probe.verdict { ... }` 请求防护动作。只有 enforcement mode、selector、
  backend 和 policy 都允许时，它才会变成 destructive action。
- sandbox 会限制 policy 代码边界。可用标准库是 `table`、`string`、`math` 和 `bit`；
  `require` 只能加载声明过的 bundle-local module；`io`、`os`、`debug`、`ffi`、`loadfile`
  等 host API 不可用。
- `runtime_error_disable_threshold` 是单个 policy 的阈值。Lua runtime error
  的 `policy_runtime_error` audit event 写入 export queue 后，连续错误计数才会推进。
  hook 成功执行会清零计数，selector miss 不改变计数。达到阈值后，agent 只禁用该
  policy，在线 admin status 会报告被禁用的 policy 和原因。设置为 `0` 可持续审计错误但不自动禁用。

Lua source：

```lua
local function header(event, wanted)
  wanted = string.lower(wanted)
  for _, pair in ipairs(event.kind.headers or {}) do
    if string.lower(pair[1]) == wanted then
      return pair[2]
    end
  end
  return nil
end

function on_http_request_headers(event)
  local host = header(event, "host") or "-"
  local target = event.kind.target or "/"

  if event.kind.method == "POST" and target == "/admin" then
    return {
      probe.emit_alert("admin POST on " .. host),
      probe.verdict {
        action = "reset",
        scope = "flow",
        reason = "admin endpoint is not allowed",
        confidence = 95,
        ttl_ms = 60000
      }
    }
  end

  return probe.emit_alert("HTTP request " .. target .. " on " .. host)
end

function on_websocket_message(event)
  if event.kind.opcode.kind ~= "text" then
    return nil
  end

  if event.kind.payload_len > 65536 then
    return probe.emit_alert("large websocket text message")
  end

  if event.kind.payload_text == nil then
    return nil
  end

  if string.find(event.kind.payload_text, "token=", 1, true) then
    return probe.emit_alert("websocket message contains token material")
  end
end
```

endpoint 格式要求：

- Export webhook（`exporters.<id>.endpoint`）：
  带 scheme 和 host 的 absolute `http://` 或 `https://` URL，例如
  `https://collector.example/probe/batches`，或本地测试用的
  `http://127.0.0.1:9000/batches`。URL credentials 会被拒绝。
  配置 exporter TLS refs 时必须使用 `https://`。
- Remote Lua policy（`policies.source.endpoint`）：
  非本地 endpoint 使用 `https://`，例如
  `https://policy.example/bundles/http-guard.toml`。只有本地测试允许 loopback
  `http://`。URL credentials 会被拒绝。
- Remote enforcement policy（`enforcement.policy.source.endpoint`）：
  与 remote Lua policy bundle 使用相同 transport 规则。
- MITM policy hook（`enforcement.interception.mitm.policy_hook.endpoint`）：
  带显式非零端口的 loopback IP `http://` URL，例如
  `http://127.0.0.1:15002/mitm-policy-hook`。hostname、credentials、fragment、
  缺失端口和 `https://` 都会被拒绝。

webhook receiver contract：

- Endpoint URL：
  带 scheme 和 host 的 absolute `http://` 或 `https://` URL。
  URL credentials 会被拒绝。TLS refs 要求 `https://`。
- Method：
  对配置的 path 和 query 发起 `POST`。
- `content-type`：
  `application/x-protobuf`。
- `x-traffic-probe-codec`：
  `none`、`zstd`、`gzip` 或 `deflate`；receiver 按这个 header 解码 body。
- `idempotency-key`：
  export batch id；receiver 应用它做 deduplication。
- Body：
  `BatchEnvelope` protobuf bytes，并按 `x-traffic-probe-codec` 压缩。
- ACK body：
  不超过 64 KiB 的 UTF-8 JSON。

ACK JSON：

```json
{
  "batch_id": "probe-local:primary-webhook:1-4",
  "accepted": true,
  "acked_cursor": 4,
  "reason": null
}
```

receiver 只有在 durable 存储了截至并包含 `acked_cursor` 的所有 record 后，才应返回
`accepted = true`。状态码非 2xx、body 不是合法 ACK JSON、`batch_id` 不匹配、
`accepted = false` 或 `acked_cursor` 超出请求 sequence 范围时，Probe 会重试该 batch。

receiver algorithm：

```text
verify POST, content-type, idempotency-key, and x-traffic-probe-codec
decode the body according to x-traffic-probe-codec
decode BatchEnvelope using docs/export-batch.proto
verify BatchEnvelope.batch_id matches idempotency-key
durably upsert records by batch_id and EventRecord.sequence
return accepted=true with the last contiguous durable sequence
```

第一次做 collector interop 时，可以使用 `codec = "none"` 或 `--codec none`，
这样 receiver 只需要先处理 protobuf 解码。等 receiver 支持 `x-traffic-probe-codec` 后，
再启用 `zstd`、`gzip` 或 `deflate`。

`agent replay --policy` 是调试入口：它接受单个 Lua 文件，并包一层 synthetic replay
manifest。可以用它在不需要 live-capture 权限的情况下验证 receiver：

```bash
cargo run -p agent --locked -- replay \
  --input examples/replay.http \
  --spool target/probe-demo/webhook-replay-spool \
  --policy examples/policies/http-alert/main.lua \
  --webhook http://127.0.0.1:9000/batches \
  --codec none \
  --agent-id probe-webhook-demo
```

### Capture

自动 live selection 会按顺序尝试 fallback backend：

```toml
[capture]
selection = "auto"
fallback_backends = ["ebpf", "libpcap"]

[capture.ebpf]
# 自定义 process-observation object 的可选 override。常规运行会使用物化到
# PROBE_HOME/artifacts/ebpf 下的内置 object。
# object_path = "/opt/traffic-probe/ebpf-process-observation.bpf.o"

[capture.libpcap]
interface = "any"
bpf_filter = "tcp"
snaplen = 65535
promisc = false
immediate_mode = true
read_timeout_ms = 1000
```

plaintext feed 是确定性输入，不需要 live capture：

```toml
[capture]
selection = "plaintext_feed"

[capture.plaintext_feed]
path = "/var/lib/traffic-probe/plaintext-feed.jsonl"
```

plaintext feed 是 JSON Lines：一行一条 event。每个 event 都重复 `connection` 对象，
这样 feed 可以 append 或 replay，不依赖隐藏进程状态。`bytes` event 使用数字 byte array、
direction 和 stream offset：

```json
{
  "type": "bytes",
  "timestamp": { "monotonic_ns": 2, "wall_time_unix_ns": 2 },
  "connection": {
    "connection_id": "local-demo-conn",
    "local": { "address": "127.0.0.1", "port": 51100 },
    "remote": { "address": "127.0.0.1", "port": 8081 },
    "protocol": "tcp",
    "start_monotonic_ns": 1,
    "attribution_confidence": 100,
    "process": {
      "pid": 4242,
      "tgid": 4242,
      "start_time_ticks": 1000,
      "boot_id": "local-demo",
      "exe_path": "/usr/bin/probe-demo-client",
      "cmdline_hash": "local-demo-client",
      "uid": 1000,
      "gid": 1000,
      "name": "probe-demo-client",
      "cmdline": ["probe-demo-client"]
    }
  },
  "direction": "outbound",
  "stream_offset": 0,
  "bytes": [71, 69, 84, 32, 47, 100, 101, 109, 111]
}
```

`connection_opened`、`connection_closed` 和 `gap` event 使用同一 connection 形状。
`gap` 包含 `expected_offset`、可选 `next_offset` 和 `reason`。

capture-event feed 接收 typed capture event，并可以 follow append：

```toml
[capture]
selection = "capture_event_feed"

[capture.capture_event_feed]
path = "/var/lib/traffic-probe/capture-events.jsonl"
follow = true
```

### Storage

live run 和 exporter cursor 需要 Fjall spool：

```toml
[storage]
path = "/var/lib/traffic-probe/spool"

[storage.retention.ingress]
max_records = 100000
sweep_interval_ms = 1000
prune_batch_limit = 1024

[storage.retention.export]
max_records = 100000
sweep_interval_ms = 1000
prune_batch_limit = 1024
```

ingress recovery 会在打开新 capture provider 前 replay 已持久化的 capture event。
active parser state 不会序列化，因此 recovery 是保守能力，并在 capability model 中报告为 degraded。
exporter ACK 只推进 per-sink cursor；export queue 的物理删除由
`storage.retention.export` 控制。

### Export

长运行 agent 应启用 worker，并配置一个或多个 sink：

```toml
[export.worker]
enabled = true

[export.worker.schedule]
mode = "fixed_interval_bounded"
interval_ms = 1000
batches_per_sink_per_tick = 1
sink_timeout_ms = 10000

[[exporters]]
id = "local-file"
transport = "file"
path = "/var/lib/traffic-probe/export/events.jsonl"
codec = "zstd"

[[exporters]]
id = "primary-webhook"
transport = "webhook"
endpoint = "https://collector.example/probe/batches"
codec = "zstd"
headers = { "x-probe-node" = "probe-local" }

[[exporters]]
id = "local-sidecar"
transport = "unix_http"
socket_path = "/var/lib/traffic-probe/run/collector.sock"
endpoint = "/probe/batches"
codec = "zstd"
headers = { "x-probe-node" = "probe-local" }
```

每个 export batch 同时受 record 数量和 stored payload bytes 约束：
最多 1024 条 records，并有 16 MiB payload-byte soft limit。单个更大的 event
仍会单独发送，避免 sink cursor 永久卡住。

支持的 codec 是 `none`、`zstd`、`gzip` 和 `deflate`；默认是 `zstd`。
webhook sink 可以引用 `[[tls.materials]]` 中的 trust anchor 和 client identity。
file sink 会创建私有 `0600` 文件，并拒绝不安全的父目录。Unix HTTP sink 通过本地
Unix domain socket 发送同一套 protobuf batch 和 ACK 协议，适合服务器本机 collector
sidecar，且不需要开放 TCP listener。

#### Webhook Receiver Setup

第一套接入章节已经给出 webhook request、ACK 和 retry contract。完整 receiver 参考见
[docs/webhook-receiver_ZH.md](docs/webhook-receiver_ZH.md)，batch schema 见
[docs/export-batch.proto](docs/export-batch.proto)，所有 HTTP surface 的 endpoint 规则见
[docs/http-endpoints_ZH.md](docs/http-endpoints_ZH.md)。

### Policy

`agent run` 使用 policy bundle。本地 bundle 是包含 `manifest.toml`、`main.lua` 和可选声明式
bundle-local module 的目录；第一套接入章节已经给出完整例子。

远程 policy bundle 在配置中声明为 bounded TOML document；response schema 和示例见
[docs/lua-policy_ZH.md](docs/lua-policy_ZH.md)，其中也包含 module 格式：

```toml
[[policies]]
id = "http-alert"
enabled = true
runtime_error_disable_threshold = 3

[policies.source]
kind = "remote_bundle"
endpoint = "https://policy.example/bundles/http-alert.toml"
max_body_bytes = 16777216
```

`agent replay --policy` 是刻意不同的调试入口：它接受单个 Lua 文件，并包一层 synthetic replay
manifest。

完整 hook 表、event 字段参考、sandbox contract、outcome model 和实用 Lua 写法见
[docs/lua-policy_ZH.md](docs/lua-policy_ZH.md)。

### TLS Material

TLS material reference 由 exporter、TLS decrypt hint 和 MITM 共享：

```toml
[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/etc/probe/certs/collector-ca.pem"

[[tls.materials]]
id = "browser-keylog"
kind = "key_log_file"
path = "/var/lib/traffic-probe/tls/browser.keys"

[[tls.materials]]
id = "mitm-ca"
kind = "mitm_ca_certificate"
path = "/etc/probe/certs/mitm-ca.pem"

[[tls.materials]]
id = "mitm-ca-key"
kind = "mitm_ca_private_key"
path = "/etc/probe/certs/mitm-ca.key"

[[tls.materials]]
id = "upstream-ca"
kind = "mitm_upstream_trust_anchor"
path = "/etc/probe/certs/upstream-ca.pem"
```

best-effort libssl plaintext instrumentation 必须显式开启。agent build 默认嵌入 first-party TLS
uprobe object。hooks 启用且未配置 override path 时，agent 会把该 object 物化到
`PROBE_HOME/artifacts/ebpf/` 下，并使用内容寻址生成的路径。应配置 selector，避免过宽
attachment：

```toml
[tls.plaintext.instrumentation]
enabled = true
reconcile_interval_ms = 1000

[tls.plaintext.instrumentation.selector]
op = "match"

[tls.plaintext.instrumentation.selector.term.process]
pids = []
names = []
exe_path_globs = ["/usr/bin/curl"]
cmdline_regexes = []
systemd_services = []
container_ids = []

[tls.plaintext.instrumentation.selector.term.traffic]
local_ports = []
remote_ports = [443]
directions = ["outbound"]
remote_addresses = []
```

`capture.ebpf.object_path` 和 `libssl_uprobe_object_path` 是自定义 eBPF artifact 的高级
override。常规安装应让生成资产保留在 `PROBE_HOME` 下，这样卸载时可以删除一个状态树。

### Enforcement 与 MITM

Enforcement 从 audit-only 开始：

```toml
[enforcement]
mode = "audit_only"
backend = "none"
```

`dry_run` 用来在不执行 destructive backend 的情况下验证 planner decision。只有在显式配置
backend、selector、policy source 并完成运维审批后，才应使用 `enforce`。

当被动 eBPF/libpcap capture 不可用时，transparent proxy 或 MITM 可以为 scoped traffic
提供可靠的普通明文 HTTP 和 TLS 解密后 HTTP 内容路径。这是显式 data-plane strategy：必须配置流量改道、
operator-managed trust、MITM backend 和 `capture_event_feed` plaintext bridge。配置该 bridge 后，
`capture.selection = "auto"` 可以在被动 capture 候选失败后使用 MITM feed。

Lua policy 产生 event-level alert 和 verdict request。Enforcement policy manifest 是独立
control input，用来定义允许应用哪些 protective action，以及可选的 process/traffic selector：

```toml
[enforcement.policy.source]
kind = "file"
path = "/etc/probe/enforcement.toml"
```

enforcement manifest 是 TOML。可运行模板在
[`examples/enforcement.toml`](examples/enforcement.toml)：

```toml
id = "managed-apps"
version = "2026-06-30"
protective_actions = ["deny", "reset"]

[selector]
op = "match"

[selector.term.process]
pids = []
names = []
exe_path_globs = ["/usr/bin/curl"]
cmdline_regexes = []
systemd_services = []
container_ids = []

[selector.term.traffic]
local_ports = []
remote_ports = [443]
directions = ["outbound"]
remote_addresses = []
```

支持的 source kind：

- `none`，不启用配置化 enforcement policy input，且不能与 `mode = "enforce"` 搭配；
- `file`，`path` 直接指向一个 manifest；
- `directory`，`path` 指向包含 `manifest.toml` 的目录；
- `remote`，`endpoint` 返回一个 bounded TOML manifest，可选 `max_body_bytes`
  限制 response body。

remote endpoint 必须是不含 credentials 的 absolute URL。除本地测试使用的 loopback HTTP
endpoint 外，必须使用 HTTPS。

`protective_actions` 只接受 `deny`、`reset` 和 `quarantine`。这样 destructive action
profile 会保持显式，并与 Lua event policy logic 分离。

命名 selector 可以集中声明，并在 capture、TLS、policy、enforcement 和 transparent
interception selector 中复用：

```toml
[selectors.managed_https]
op = "match"

[selectors.managed_https.term.process]
names = ["curl"]
exe_path_globs = []
cmdline_regexes = []
systemd_services = []
container_ids = []

[selectors.managed_https.term.traffic]
remote_ports = [443]
directions = ["outbound"]
remote_addresses = []

[enforcement.interception.selector]
op = "ref"
name = "managed_https"
```

Enforcement manifest 也可以声明自己的 `[selectors.<name>]` registry。manifest 中的
ref 会先在 manifest 命名空间内解析，再与主配置 selector 合成。

selector 的 list 字段省略时默认是空列表。空的 process 或 traffic 维度表示“不限制该维度”，
不是解析错误。

Selector 组合 process 和 traffic 维度：

```toml
[enforcement.interception.selector]
op = "match"

[enforcement.interception.selector.term.process]
pids = []
names = []
exe_path_globs = ["/usr/bin/curl"]
cmdline_regexes = []
systemd_services = []
container_ids = []

[enforcement.interception.selector.term.traffic]
local_ports = []
remote_ports = [443]
directions = ["outbound"]
remote_addresses = []
```

Linux socket destroy 只关闭已存在的 TCP socket。它使用 `NETLINK_SOCK_DIAG`
和 `SOCK_DESTROY`，并在 capability 可用前执行 active loopback self-test。
它不是 pre-connect deny、UDP blocking，也不是 payload-level blocking。成功销毁会在导出的
`EnforcementDecision` 中写入 typed `connection_backend/linux_socket_destroy` mechanism
evidence；顶层 `effective_action` 表达 planner 接受的策略动作。

Transparent MITM 是独立 strategy。它需要 root/net-admin、operator-managed client trust、
certificate material refs、proxy listener 设置、backend readiness、plaintext bridge 配置和
scoped selector。下面的 fragment 假设前面的 TLS material refs 已经配置：

```toml
[enforcement]
mode = "enforce"
backend = "none"

[enforcement.policy.source]
kind = "file"
path = "/etc/probe/enforcement.toml"

[enforcement.interception.selector]
op = "match"

[enforcement.interception.selector.term.process]
pids = []
names = []
exe_path_globs = []
cmdline_regexes = []
systemd_services = []
container_ids = []

[enforcement.interception.selector.term.traffic]
local_ports = [443]
remote_ports = []
directions = ["inbound"]
remote_addresses = []

[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
self_bypass = "none"
listen_port = 15001

[enforcement.interception.mitm]
ca_certificate_ref = "mitm-ca"
ca_private_key_ref = "mitm-ca-key"
upstream_trust_anchor_refs = ["upstream-ca"]

[enforcement.interception.mitm.client_trust]
mode = "operator_managed"

[enforcement.interception.mitm.backend]
mode = "product_proxy"

[enforcement.interception.mitm.backend.process.launcher]
mode = "external_binary"
program = "/usr/local/bin/traffic-probe-mitm-proxy"

[[enforcement.interception.mitm.backend.process.upstream_routes]]
host = "service.example.com"
target = "127.0.0.1:18443"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15001"

[enforcement.interception.mitm.plaintext_bridge]
mode = "capture_event_feed"
path = "/var/lib/traffic-probe/mitm/feed.jsonl"
follow = true

[enforcement.interception.mitm.policy_hook]
mode = "http_json"
endpoint = "http://127.0.0.1:15002/mitm-policy-hook"
```

first-party product proxy 支持 exact 和 suffix-wildcard upstream route。opt-in DNS discovery
可作为 fallback；默认拒绝 IANA special-purpose/special-use address，除非显式允许。
CA-backed dynamic certificate mode 要求下游 client 发送 DNS SNI。Host/SNI mismatch 会 fail
closed。若希望 proxy 从同一个 agent binary 启动，使用 `launcher.mode = "embedded_agent"`，
并将 `program` 指向 `/usr/local/bin/traffic-probe`；独立 `traffic-probe-mitm-proxy` binary
使用 `external_binary`。

### Admin 与 Status

需要 online reload 时启用 admin socket：

```toml
[admin]
enabled = true
socket_path = "/run/traffic-probe/admin.sock"

[admin.prometheus]
enabled = true
listen_addr = "127.0.0.1:9464"
```

首次生成的配置会启用主配置 watcher。守护进程部署中，watcher 会观察 `--config` 文件及其父目录，
对编辑器写入和 atomic replace 做 debounce，然后复用 admin socket 和 TUI 使用的
`apply-config-reload` 契约。TUI-managed agent 子进程会关闭自身 watcher，因为 TUI 已经负责这些临时
runtime config 的 runtime reconciliation。若 data-path generation request 正在 pending 或 applying，
watcher 会等待 generation 空闲，重新读取配置文件，并按最新文件内容重试：

```toml
[runtime_reload]
watch_config = true
debounce_ms = 500
```

admin reload 会先校验新 policy 或 enforcement state，再替换 runtime state。
`reload-runtime-actions` 会执行 active `RuntimePlan` 下安全的 runtime action，并独立报告每个
action 的结果，因此 enforcement reload 失败不会掩盖 policy reload 成功。CLI 会先打印完整 JSON response，
再在任一 action outcome 为 `failed` 时以非零状态退出。候选主配置可以通过
`plan-config-reload` 解析并做静态校验，报告 `no_change`、`apply_online`、
`queue_runtime_generation`、`restart_required` 或 `invalid_candidate`。每个 changed section
携带 `reload_mode`：`apply_online`、`runtime_generation` 或 `process_restart`。
`apply-config-reload` 只会对单个 online owner 更新 active plan，或提交纯 data-path runtime
generation request；后者不会提前替换 active plan。
policy-only 主配置变更在本地 watcher 和远程 poller topology 未启用时可在线应用；enforcement
policy source 和 `enforcement.selector` 变更在 enforcement reload watcher/poller topology 未启用且
transparent interception 未持有 setup-time host rules 时可在线应用。顶层 `[selectors]` registry 变更，
包括被 `enforcement.selector` 引用的条目变更，仍需要重启。
Data-path rebuild verdict 会提交带 request id 的 `request_runtime_generation` action，并在 status 中表现为
pending runtime generation；live agent 在 capture safe point 消费该 request 并记录 runtime generation outcome。
capture、observation、config version、TLS plaintext instrumentation 和 TLS decrypt-hint material
变更会构建候选 capture generation，只有候选 provider 打开成功后才交换到 live loop、更新 runtime
status 并替换共享 active plan。online/data-path 混合变更保持 `restart_required`，直到存在能整体
应用候选配置且不会产生 partial commit 的事务型 generation owner。generation request 无法入队时，
旧 runtime 保持活跃；TUI-managed agent 可以通过重启收敛到保存配置，attached external agent 会提示
显式重启或重试。selectors、MITM/export TLS materials、enforcement execution surface、export、
storage、admin、agent id 和 watcher topology 变更不会被该路径静默应用，在对应 lifecycle owner
存在前保持 `restart_required`。

Prometheus listener 是只读、loopback-only 的 `GET /metrics` surface；控制命令仍留在私有 Unix
socket。runtime status 和 metrics 会暴露 capture input activity、pipeline progress、
spool/export state、policy/enforcement counters、TLS plaintext activity 和 proxy health。
capture input activity 包含最近 signal kind、sequence 和 observation time，但不把该 activity 解释为
kernel link liveness。eBPF provider status 会分别报告已持有的 tracepoint links 和
optional kernel tracepoint-pair availability，例如 `sendfile` 或 `sendfile64`。
admin CLI 会通过 Unix socket 发送同一套 JSON-lines 命令：

```bash
cargo run -p agent -- admin \
  --socket /run/traffic-probe/admin.sock \
  status

cargo run -p agent -- admin \
  --socket /run/traffic-probe/admin.sock \
  plan-config-reload --config /etc/probe/agent.toml

cargo run -p agent -- admin \
  --socket /run/traffic-probe/admin.sock \
  reload-runtime-actions

cargo run -p agent -- admin \
  --socket /run/traffic-probe/admin.sock \
  reload-policies

cargo run -p agent -- admin \
  --socket /run/traffic-probe/admin.sock \
  prometheus-metrics

cargo run -p agent -- admin \
  --socket /run/traffic-probe/admin.sock \
  tail-events --after-sequence 0 --limit 50 \
  --process-exe-glob /usr/bin/curl

cargo run -p agent -- admin \
  --socket /run/traffic-probe/admin.sock \
  event-detail --sequence 42

cargo run -p agent -- admin \
  --socket /run/traffic-probe/admin.sock \
  debug-dump
```

`tail-events` 是 durable export queue 上的有界、非 mutating view。它面向自动化返回完整
event envelope，并只推进响应中的 `next_after_sequence`；它不会 ack exporter sink cursor。
它只能读取仍被 `storage.retention.export` 保留的 records。超出 byte budget 的大事件会以
omission metadata 表达，而不是无界展开到响应中。
`event-detail --sequence <n>` 是单条事件检查接口。它按 sequence 读取仍被保留的一个
export event；TUI 在 bounded tail row 需要完整 payload 详情时使用该接口。它会在单响应
detail budget 内返回完整事件；超过该预算的记录返回 `event_detail_too_large` metadata，
不会返回截断 payload。
`debug-dump` 复用在线 status snapshot，并附带 admin protocol metadata。它包含
runtime plan/status 字段和本地路径，但不包含 raw config 文本或 secret material 字节。

本地 watcher 和 remote polling 都需要显式开启。本地 source 使用本地触发器：

```toml
[policy_reload]
watch_local_bundles = true
debounce_ms = 500

[enforcement.policy.source]
kind = "file"
path = "/etc/probe/enforcement.toml"

[enforcement.policy.reload]
watch_local_manifest = true
debounce_ms = 500
```

remote source 使用 remote polling：

```toml
[policy_reload]
poll_remote_bundles = true
remote_poll_interval_ms = 60000

[enforcement.policy.source]
kind = "remote"
endpoint = "https://policy.example/probe/enforcement.toml"

[enforcement.policy.reload]
poll_remote_manifest = true
remote_poll_interval_ms = 60000
```

remote polling 会按固定间隔重新加载当前配置的 remote source。policy polling 会校验未变化的
bundle，但 content 未变化时不会替换 active Lua VM。加载失败会保留上一份 active policy 或
enforcement manifest。

## 运维命令

```bash
agent capabilities
agent check --config ./agent.toml
agent status --config ./agent.toml
agent run --config ./agent.toml
agent replay --input ./traffic.http --spool ./spool --policy ./policy.lua
```

`capabilities`、`check` 和 `status` 返回适合自动化消费的 JSON。runtime validation 失败时，
`check` 会输出包含 violations 和 capability matrix 的 `invalid_config` JSON report，然后以非零状态退出。
`run` 启动配置化 agent。`replay` 将单个 byte stream 接入同一 parser、policy、spool 和可选
webhook path，不需要 live-capture 权限。

## 验证

E2E profile 按 capability claim 组织：

- `baseline` 以普通用户运行，覆盖 local validation、replay、plaintext feed、gap/loss event、
  HTTP/SSE/WebSocket、webhook/file/Unix HTTP export，以及一次性和后台 polling remote
  policy input，并覆盖不依赖透明主机规则的 first-party product MITM proxy 明文/TLS feed ingestion。
- `live-core` 需要 root 或 CAP_NET_RAW，覆盖 libpcap loopback、单项和组合 admin reload、
  socket destroy 和 TLS key log/session-secret material。
- `process-ebpf` 需要 root/bpffs，覆盖 eBPF process observation 和真实 process
  ring-buffer output loss。
- `tls-plaintext` 需要 root/bpffs，覆盖 libssl plaintext provider、attach lifecycle
  和真实 TLS plaintext ring-buffer output loss。
- `transparent-interception` 需要 root/net-admin，覆盖 inbound TPROXY、outbound proxy、
  MITM plaintext bridge、policy hook 和 product proxy HTTPS/WebSocket path。
- `linux-artifacts` 需要 root/net-admin，覆盖 Linux transparent interception artifact
  acceptance。
- `product` 组合 user、live、eBPF、TLS、interception、MITM 和 Linux artifact suite。

列出 case、profile 和机器可读覆盖信息：

```bash
cargo run -p xtask --locked -- e2e-suite --list
cargo run -p xtask --locked -- e2e-suite --list-profiles
cargo run -p xtask --locked -- e2e-suite --inventory-json
```

`--list` 输出每个 case 的权限需求和 capability ID。`--list-profiles`
输出每个 profile 的权限集合、capability 并集、说明和展开后的 case 列表。
`--inventory-json` 从同一个 registry 输出 schema version 2：capability
catalog 带 category metadata，case coverage 和 profile coverage 都从单一事实源派生。

运行单机验证路径：

```bash
cargo run -p xtask --locked -- validate-local
```

运行非特权 baseline：

```bash
cargo run -p xtask --locked -- e2e-suite --profile baseline
```

在隔离开发环境中运行 privileged profile：

```bash
sudo target/debug/xtask e2e-suite --profile live-core
sudo target/debug/xtask e2e-suite --profile process-ebpf
sudo target/debug/xtask e2e-suite --profile tls-plaintext
sudo target/debug/xtask e2e-suite --profile transparent-interception
```

privileged case 可能会操作 network namespace、bpffs、nftables、policy routing 或 live socket。

## 边界

Probe 不声明以下能力：

- 默认全机 transparent MITM；
- 自动修改 client trust store；
- HTTP/2、HTTP/3 或 QUIC parser；
- 所有 MITM path 的强原始归因；
- 除已覆盖 WebSocket tunnel 行为以外的 non-HTTP transparent allow-path matrix；
- 通过 Linux socket destroy 实现 pre-connect deny、UDP blocking 或 payload-level blocking；
- 隐藏式长期原始流量保存；
- 在 runtime 已报告 degraded evidence 时仍宣称 best-effort live capture 完整。

详细设计源、能力事实和验证矩阵见 [docs/design.md](docs/design.md)。

## 仓库结构

| 路径 | 职责 |
| --- | --- |
| `crates/core` | event contract、selector、process/flow identity、verdict、capability model |
| `crates/config` | TOML config model 和 validation |
| `crates/runtime` | runtime plan 和 capability validation |
| `crates/capture` | capture provider、eBPF/libpcap path、TLS plaintext bridge |
| `crates/parsers` | parser trait 和 HTTP/SSE/WebSocket implementation |
| `crates/policy` | Lua policy runtime 和 event view |
| `crates/enforcement` | scoped enforcement planner 和 backend/hook contract |
| `crates/pipeline` | capture-to-parser-to-policy-to-spool execution |
| `crates/agent` | runtime composition、config loading、status/admin surface |
| `crates/storage` | Fjall durable spool 和 cursor-backed queue |
| `crates/exporter` | export batch、codec、webhook transport、file transport |
| `crates/mitm-proxy` | first-party L7 MITM product proxy |
| `crates/transparent-linux` | Linux transparent interception artifact planning |
| `crates/xtask` | end-to-end validation harness |
| `examples` | 可运行 demo input 和带注释 config template |

## 贡献

高价值贡献通常会增强这些方面：

- 更强的 process/socket attribution；
- 更清晰的 capability 和 degradation reporting；
- 更安全的 enforcement boundary；
- 通过现有 parser trait 扩展协议覆盖；
- durable export transport；
- 高信号 E2E 覆盖。

提交修改前运行：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test --workspace --locked
```

## License

Probe 采用双协议授权，你可以任选其一：

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
