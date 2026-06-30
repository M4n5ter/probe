# Lua Policy Reference

Probe policy bundles let operators inspect typed traffic events and return
structured outcomes. A policy is not a packet filter and does not receive raw
kernel objects. It receives a stable Lua table derived from the event model.

## Bundle Layout

A local bundle is a directory containing `manifest.toml` and `main.lua`:

```text
policy/
  manifest.toml
  main.lua
```

`manifest.toml` declares the bundle identity and the hooks that Probe should
call:

```toml
id = "http-guard"
version = "2026-06-30"
hooks = [
  "on_http_request_headers",
  "on_http_response_headers",
  "on_websocket_message",
]
```

Every hook named in the manifest must be implemented as a global Lua function
with the same name. `agent check` validates this before the policy becomes
active.

## Runtime Model

Each hook receives one `event` table and may return no outcome, one outcome, or
an array of outcomes. Hooks should be deterministic and bounded. Probe resets
the instruction budget for each hook invocation and records runtime failures as
policy runtime error events.

Allowed Lua standard libraries are `table`, `string`, `math`, and `bit`. Host
capabilities are removed: `require`, `io`, `os`, `package`, `debug`, `ffi`,
`jit`, `dofile`, `loadfile`, `load`, and `collectgarbage` are unavailable.

## Hook Names

| Hook | Delivered event |
| --- | --- |
| `on_connection_opened` | A flow opened. |
| `on_connection_closed` | A flow closed. |
| `on_http_request_headers` | HTTP request line and headers. |
| `on_http_response_headers` | HTTP response line and headers. |
| `on_http_body_chunk` | Bounded HTTP body bytes. |
| `on_sse_event` | Server-Sent Events semantic event. |
| `on_websocket_handoff` | HTTP Upgrade handoff into WebSocket mode. |
| `on_websocket_frame` | Individual WebSocket frame metadata. |
| `on_websocket_message` | Reassembled bounded WebSocket message metadata. |
| `on_opaque_stream` | Bytes that could not be parsed as a supported protocol. |
| `on_gap` | Parser or provider gap. |
| `on_protocol_error` | Protocol parse error. |

Events such as policy alerts, verdicts, runtime errors, enforcement decisions,
capture loss, and MITM audit records are audit output. They are not delivered
back into Lua.

## Common Event Fields

Every policy input has these fields:

| Field | Meaning |
| --- | --- |
| `event.id` | Stable event id. |
| `event.event_type` | String event type, such as `http_request_headers`. |
| `event.timestamp.monotonic_ns` | Monotonic timestamp. |
| `event.timestamp.wall_time_unix_ns` | Unix wall-clock timestamp in nanoseconds. |
| `event.origin.source` | Capture source. Common values are listed below. |
| `event.origin.provider` | Provider kind, such as `libpcap`, `ebpf`, `plaintext`, `interception`, or `replay`. |
| `event.config_version` | Agent config version string. |
| `event.policy_version` | Policy version when present. |
| `event.degraded` | `true` when evidence is known to be incomplete. |
| `event.direction` | `inbound`, `outbound`, or `nil` when the event is not directional. |
| `event.enforcement_evidence.kind` | `destructive_allowed` or `observation_only`. |
| `event.kind.type` | Event-specific kind discriminator. |

`event.flow` carries process and socket attribution:

| Field | Meaning |
| --- | --- |
| `event.flow.id` | Flow id. |
| `event.flow.protocol` | `tcp` or `udp`. |
| `event.flow.local_endpoint.address` / `.port` | Local endpoint. |
| `event.flow.remote_endpoint.address` / `.port` | Remote endpoint. |
| `event.flow.start_monotonic_ns` | Flow start timestamp. |
| `event.flow.socket_cookie` | Kernel socket cookie when known. |
| `event.flow.attribution_confidence` | `0..100` process attribution confidence. |
| `event.flow.process.name` | Process name. |
| `event.flow.process.cmdline` | Command-line vector. |
| `event.flow.process.identity.*` | Process identity fields. Common fields are listed below. |

Common capture source values include:

- `libpcap`
- `ebpf_syscall`
- `libssl_uprobe`
- `tls_session_secret`
- `external_plaintext_feed`
- `l7_mitm_plaintext`
- `replay`

Process identity fields include PID, TGID, UID, GID, executable path, boot id,
cgroup, systemd service, container id, runtime hint, and command-line hash.

## Event-Specific Fields

| `event.kind.type` | Fields |
| --- | --- |
| `connection_opened` | No additional fields. |
| `connection_closed` | No additional fields. |
| `http_request_headers` | `direction`, `stream_sequence`, `method`, `target`, `version`, `headers`. |
| `http_response_headers` | `direction`, `stream_sequence`, `status`, `reason`, `version`, `headers`. |
| `http_body_chunk` | `direction`, `stream_sequence`, `offset`, `data`, `end_stream`. |
| `sse_event` | `direction`, `stream_sequence`, `event`, `id`, `retry_ms`, `data`. |
| `websocket_handoff` | `direction`, `stream_sequence`, `target`, `subprotocol`, `extensions`. |
| `websocket_frame` | See WebSocket frame fields below. |
| `websocket_message` | See WebSocket message fields below. |
| `opaque_stream` | `direction`, `fingerprint`, `reason`. |
| `gap` | `direction`, `expected_offset`, `next_offset`, `reason`. |
| `protocol_error` | `direction`, `reason`. |

WebSocket frame fields:

- `direction`
- `stream_sequence`
- `frame_sequence`
- `fin`, `rsv1`, `rsv2`, `rsv3`
- `opcode`
- `payload_len`
- `masked`
- `payload_fingerprint`

WebSocket message fields:

- `direction`
- `stream_sequence`
- `message_sequence`
- `first_frame_sequence`
- `final_frame_sequence`
- `opcode`
- `payload_len`
- `payload_fingerprint`

`headers` is a 1-indexed array of two-element arrays:
`{ { "host", "example.test" }, ... }`. Read `pair[1]` for the name and
`pair[2]` for the value. Header names preserve the event payload
representation; policy code should compare case-insensitively.

WebSocket `opcode` is a tagged table. For frames,
`event.kind.opcode.kind` is one of `continuation`, `text`, `binary`, `close`,
`ping`, `pong`, or `other`; `other` also has `code`. For reassembled messages,
the opcode kind is `text` or `binary`.

`data` fields are bounded byte arrays or strings depending on event kind. Byte
arrays and fingerprints are 1-indexed arrays of integer byte values, and
fingerprints are not plaintext payload retention.

## Outcomes

Return `nil` to emit nothing:

```lua
function on_http_request_headers(_)
  return nil
end
```

Return an alert:

```lua
function on_http_request_headers(event)
  return probe.emit_alert("HTTP " .. event.kind.method .. " " .. event.kind.target)
end
```

Return a verdict:

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

Return multiple outcomes:

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

Valid verdict actions are `allow`, `observe`, `alert`, `deny`, `reset`, and
`quarantine`. Valid scopes are `flow`, `request`, `response`, and `chunk`.
Protective actions only become destructive when the configured enforcement
policy, selector, backend, and runtime mode allow them.

## Practical Patterns

Use a small local helper for header lookup:

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

Inspect SSE events without body parsing:

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

Inspect WebSocket message metadata:

```lua
function on_websocket_message(event)
  if event.kind.opcode.kind == "text" and event.kind.payload_len > 65536 then
    return probe.emit_alert("large text websocket message")
  end
end
```

Treat degraded evidence conservatively:

```lua
function on_http_request_headers(event)
  if event.degraded then
    return probe.emit_alert("degraded HTTP evidence from " .. event.origin.source)
  end
end
```

## Configure And Validate

Reference a local bundle from the agent config:

```toml
[[policies]]
id = "http-guard"
enabled = true

[policies.source]
kind = "local_directory"
path = "/etc/probe/policies/http-guard"
```

Reference a remote bundle:

```toml
[[policies]]
id = "http-guard"
enabled = true

[policies.source]
kind = "remote_bundle"
endpoint = "https://policy.example/bundles/http-guard.toml"
max_body_bytes = 16777216
```

Remote policy endpoints must be HTTPS, except loopback HTTP endpoints used for
local testing. Credentials in URLs are rejected.

The endpoint response body is one TOML document. The `source` field carries the
Lua source that would otherwise be stored in `main.lua`; the `[manifest]` table
uses the same schema as a local `manifest.toml`. Unknown top-level or manifest
fields are rejected.

```toml
source = '''
function on_http_request_headers(event)
  return probe.emit_alert("HTTP " .. event.kind.method .. " " .. event.kind.target)
end
'''

[manifest]
id = "http-guard"
version = "2026-06-30"
hooks = ["on_http_request_headers"]
```

Validate before running:

```bash
cargo run -p agent --locked -- check --config ./agent.toml
cargo run -p agent --locked -- status --config ./agent.toml
```

For local debugging, `agent replay --policy` accepts a single Lua file and wraps
it in a synthetic replay manifest:

```bash
cargo run -p agent --locked -- replay \
  --input examples/replay.http \
  --spool target/probe-demo/replay-spool \
  --policy examples/policies/http-alert/main.lua \
  --agent-id probe-replay-demo
```
