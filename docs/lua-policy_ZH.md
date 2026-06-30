# Lua Policy 参考

Probe policy bundle 用于检查类型化流量事件，并返回结构化 outcome。policy 不是 packet filter，
也不会接收裸 kernel object。它接收的是从事件模型派生出的稳定 Lua table。

## Bundle 布局

本地 bundle 是一个包含 `manifest.toml` 和 `main.lua` 的目录：

```text
policy/
  manifest.toml
  main.lua
```

`manifest.toml` 声明 bundle 身份和 Probe 需要调用的 hook：

```toml
id = "http-guard"
version = "2026-06-30"
hooks = [
  "on_http_request_headers",
  "on_http_response_headers",
  "on_websocket_message",
]
```

manifest 中的每个 hook 都必须在 `main.lua` 中实现为同名全局函数。`agent check` 会在 policy
生效前校验这一点。

## Runtime 模型

每个 hook 接收一个 `event` table，并可以返回无 outcome、一个 outcome 或多个 outcome。hook
应该保持确定性和有界执行。Probe 会为每次 hook 调用重置 instruction budget，并把 runtime failure
记录成 policy runtime error event。

允许使用的 Lua 标准库是 `table`、`string`、`math` 和 `bit`。Host capability 会被移除：
`require`、`io`、`os`、`package`、`debug`、`ffi`、`jit`、`dofile`、`loadfile`、`load`
和 `collectgarbage` 都不可用。

## Hook 名称

| Hook | 事件 |
| --- | --- |
| `on_connection_opened` | flow 打开。 |
| `on_connection_closed` | flow 关闭。 |
| `on_http_request_headers` | HTTP request line 和 headers。 |
| `on_http_response_headers` | HTTP response line 和 headers。 |
| `on_http_body_chunk` | 有界 HTTP body bytes。 |
| `on_sse_event` | Server-Sent Events 语义事件。 |
| `on_websocket_handoff` | HTTP Upgrade 进入 WebSocket mode。 |
| `on_websocket_frame` | 单个 WebSocket frame metadata。 |
| `on_websocket_message` | 重组后的有界 WebSocket message metadata。 |
| `on_opaque_stream` | 无法解析为已支持协议的字节流。 |
| `on_gap` | parser 或 provider gap。 |
| `on_protocol_error` | 协议解析错误。 |

policy alert、verdict、runtime error、enforcement decision、capture loss 和 MITM audit record
是审计输出，不会再回送给 Lua。

## 通用事件字段

每个 policy input 都包含以下字段：

| 字段 | 含义 |
| --- | --- |
| `event.id` | 稳定 event id。 |
| `event.event_type` | 字符串事件类型，例如 `http_request_headers`。 |
| `event.timestamp.monotonic_ns` | 单调时间戳。 |
| `event.timestamp.wall_time_unix_ns` | Unix wall-clock 纳秒时间戳。 |
| `event.origin.source` | capture source。常见值见下方列表。 |
| `event.origin.provider` | provider kind，例如 `libpcap`、`ebpf`、`plaintext`、`interception` 或 `replay`。 |
| `event.config_version` | agent config version。 |
| `event.policy_version` | 可选 policy version。 |
| `event.degraded` | 证据已知不完整时为 `true`。 |
| `event.direction` | `inbound`、`outbound`，或无方向事件的 `nil`。 |
| `event.enforcement_evidence.kind` | `destructive_allowed` 或 `observation_only`。 |
| `event.kind.type` | 事件专属 kind discriminator。 |

`event.flow` 携带进程与 socket 归因：

| 字段 | 含义 |
| --- | --- |
| `event.flow.id` | flow id。 |
| `event.flow.protocol` | `tcp` 或 `udp`。 |
| `event.flow.local_endpoint.address` / `.port` | 本地 endpoint。 |
| `event.flow.remote_endpoint.address` / `.port` | 远端 endpoint。 |
| `event.flow.start_monotonic_ns` | flow 起始时间戳。 |
| `event.flow.socket_cookie` | 可用时的 kernel socket cookie。 |
| `event.flow.attribution_confidence` | `0..100` 进程归因置信度。 |
| `event.flow.process.name` | 进程名。 |
| `event.flow.process.cmdline` | 命令行数组。 |
| `event.flow.process.identity.*` | 进程身份字段。常见字段见下方说明。 |

常见 capture source 值包括：

- `libpcap`
- `ebpf_syscall`
- `libssl_uprobe`
- `tls_session_secret`
- `external_plaintext_feed`
- `l7_mitm_plaintext`
- `replay`

进程身份字段包括 PID、TGID、UID、GID、可执行路径、boot id、cgroup、systemd service、
container id、runtime hint 和 command-line hash。

## 事件专属字段

| `event.kind.type` | 字段 |
| --- | --- |
| `connection_opened` | 无额外字段。 |
| `connection_closed` | 无额外字段。 |
| `http_request_headers` | `direction`、`stream_sequence`、`method`、`target`、`version`、`headers`。 |
| `http_response_headers` | `direction`、`stream_sequence`、`status`、`reason`、`version`、`headers`。 |
| `http_body_chunk` | `direction`、`stream_sequence`、`offset`、`data`、`end_stream`。 |
| `sse_event` | `direction`、`stream_sequence`、`event`、`id`、`retry_ms`、`data`。 |
| `websocket_handoff` | `direction`、`stream_sequence`、`target`、`subprotocol`、`extensions`。 |
| `websocket_frame` | 见下方 WebSocket frame 字段。 |
| `websocket_message` | 见下方 WebSocket message 字段。 |
| `opaque_stream` | `direction`、`fingerprint`、`reason`。 |
| `gap` | `direction`、`expected_offset`、`next_offset`、`reason`。 |
| `protocol_error` | `direction`、`reason`。 |

WebSocket frame 字段：

- `direction`
- `stream_sequence`
- `frame_sequence`
- `fin`、`rsv1`、`rsv2`、`rsv3`
- `opcode`
- `payload_len`
- `masked`
- `payload_fingerprint`

WebSocket message 字段：

- `direction`
- `stream_sequence`
- `message_sequence`
- `first_frame_sequence`
- `final_frame_sequence`
- `opcode`
- `payload_len`
- `payload_fingerprint`

`headers` 是 1-indexed two-element array 的数组：
`{ { "host", "example.test" }, ... }`。`pair[1]` 是 name，`pair[2]` 是 value。
header name 会保留事件 payload 中的表达，policy 代码比较时应使用大小写不敏感匹配。

WebSocket `opcode` 是 tagged table。frame 中 `event.kind.opcode.kind` 可以是
`continuation`、`text`、`binary`、`close`、`ping`、`pong` 或 `other`；`other` 还包含
`code`。重组 message 的 opcode kind 是 `text` 或 `binary`。

`data` 字段根据事件类型可能是有界 byte array 或字符串。byte array 和 fingerprint 都是
1-indexed integer byte value 数组；fingerprint 不代表保留明文 payload。

## Outcome

返回 `nil` 表示不产生输出：

```lua
function on_http_request_headers(_)
  return nil
end
```

返回 alert：

```lua
function on_http_request_headers(event)
  return probe.emit_alert("HTTP " .. event.kind.method .. " " .. event.kind.target)
end
```

返回 verdict：

```lua
function on_http_request_headers(event)
  if event.kind.method == "POST" and event.kind.target == "/admin" then
    return probe.verdict {
      action = "reset",
      scope = "flow",
      reason = "admin endpoint is not allowed",
      confidence = 95,
      ttl_ms = 60000
    }
  end
end
```

返回多个 outcome：

```lua
function on_http_request_headers(event)
  if event.kind.target == "/admin" then
    return {
      probe.emit_alert("admin route observed"),
      probe.verdict {
        action = "deny",
        scope = "request",
        reason = "admin route denied by policy",
        confidence = 100
      }
    }
  end
end
```

合法 verdict action 是 `allow`、`observe`、`alert`、`deny`、`reset` 和 `quarantine`。
合法 scope 是 `flow`、`request`、`response` 和 `chunk`。protective action 只有在
enforcement policy、selector、backend 和 runtime mode 都允许时才会产生破坏性动作。

## 实用模式

用小 helper 做 header 查找：

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
  if event.kind.target == "/debug" then
    return probe.emit_alert("debug route on " .. host)
  end
end
```

检查 SSE 语义事件，不需要自己解析 body：

```lua
function on_sse_event(event)
  if event.kind.event == "admin" then
    return probe.verdict {
      action = "alert",
      scope = "response",
      reason = "admin SSE event observed",
      confidence = 90
    }
  end
end
```

检查 WebSocket message metadata：

```lua
function on_websocket_message(event)
  if event.kind.opcode.kind == "text" and event.kind.payload_len > 65536 then
    return probe.emit_alert("large text websocket message")
  end
end
```

保守处理 degraded evidence：

```lua
function on_http_request_headers(event)
  if event.degraded then
    return probe.emit_alert("degraded HTTP evidence from " .. event.origin.source)
  end
end
```

## 配置与校验

在 agent config 中引用本地 bundle：

```toml
[[policies]]
id = "http-guard"
enabled = true

[policies.source]
kind = "local_directory"
path = "/etc/probe/policies/http-guard"
```

引用远程 bundle：

```toml
[[policies]]
id = "http-guard"
enabled = true

[policies.source]
kind = "remote_bundle"
endpoint = "https://policy.example/bundles/http-guard.toml"
max_body_bytes = 16777216
```

remote policy endpoint 必须使用 HTTPS；本地测试用 loopback HTTP 例外。URL credentials 会被拒绝。

运行前校验：

```bash
cargo run -p agent --locked -- check --config ./agent.toml
cargo run -p agent --locked -- status --config ./agent.toml
```

本地调试时，`agent replay --policy` 接受单个 Lua 文件，并包成 synthetic replay manifest：

```bash
cargo run -p agent --locked -- replay \
  --input examples/replay.http \
  --spool target/probe-demo/replay-spool \
  --policy examples/policies/http-alert/main.lua \
  --agent-id probe-replay-demo
```
