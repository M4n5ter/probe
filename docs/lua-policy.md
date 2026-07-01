# Lua Policy Reference

Probe policy bundles let operators inspect typed traffic events and return
structured outcomes. A policy is not a packet filter and does not receive raw
kernel objects. It receives a stable Lua table derived from the event model.

## Bundle Layout

A local bundle is a directory containing `manifest.toml`, `main.lua`, and
optional bundle-local Lua modules:

```text
policy/
  manifest.toml
  main.lua
  modules/
    guard/
      matcher.lua
```

`manifest.toml` declares the bundle identity and the hooks that Probe should
call. If the policy uses bundle-local modules, each module name must be listed
explicitly:

```toml
id = "http-guard"
version = "2026-06-30"
hooks = [
  "on_http_request_headers",
  "on_http_response_headers",
  "on_websocket_message",
]
modules = ["guard.matcher"]
```

Every hook named in the manifest must be implemented as a global Lua function
with the same name. `agent check` validates this before the policy becomes
active.

Bundle-local modules are loaded with `require("guard.matcher")`. Module names
must be dotted Lua identifiers and map to `modules/guard/matcher.lua` in local
bundles. Undeclared modules, duplicate module names, symlinked module files, and
oversized module sources are rejected. A bundle may declare up to 64 modules.
Every declared module is syntax-checked before the bundle becomes active, but
module bodies still execute lazily on first `require`. Module source is a Lua
chunk; return a module value explicitly with `return M` rather than using a bare
expression.

## Runtime Model

Each hook receives one `event` table and may return no outcome, one outcome, or
an array of outcomes. Hooks should be deterministic and bounded. Probe resets
the instruction budget for each hook invocation and records runtime failures as
policy runtime error events.

Allowed Lua standard libraries are `table`, `string`, `math`, and `bit`.
`require` is replaced by a bundle-local module loader that can load only modules
declared by the bundle manifest. Host capabilities are removed: `io`, `os`,
`package`, `debug`, `ffi`, `jit`, `dofile`, `loadfile`, `load`, and
`collectgarbage` are unavailable.

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
| `on_websocket_message` | Reassembled bounded WebSocket message. |
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
| `event.enforcement_evidence.reason` | Present for `observation_only`; values are listed below. |
| `event.enforcement_evidence.detail` | Optional human-readable detail for `observation_only`. |
| `event.kind.type` | Event-specific kind discriminator. |

Observation-only reasons:

| Reason | Trigger | Scope | Policy guidance |
| --- | --- | --- | --- |
| `ebpf_syscall_payload_snapshot` | eBPF syscall payload bytes or byte-range gaps from bounded syscall sampling. | Flow-carried until the flow is closed or removed. | Treat payload as best-effort. Destructive enforcement is rejected. |
| `ebpf_unresolved_flow` | eBPF observed a socket action but could not resolve it to a strong flow identity. | Event-local. | Use for audit and telemetry, not connection enforcement. |
| `ebpf_process_lifecycle_boundary` | Process exit or exec invalidated fd-table continuity for active payload-tracked flows. | Flow-carried until the flow is closed or removed. | Treat later parser output on that flow as observation-only. |
| `provider_state_boundary` | Provider userspace state was displaced, such as tracked-flow capacity eviction. | Event-local terminal flow boundary. | Treat as a payload continuity break that does not depend on a later close. |
| `provider_capture_loss` | The capture provider reported lost observations that may affect active tracked flows. | Flow-carried fan-out gap; provider-level capture loss is audit/export output and is not delivered to Lua. | Assume bytes, lifecycle, or parser state may be incomplete. |

`event.enforcement_evidence.detail` is diagnostic text. Policies must not parse
it as a stable API.

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
- `payload_text` for complete UTF-8 text payloads up to 64 KiB
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
fingerprints are not plaintext payload retention. WebSocket message payload
bytes are retained in exported events, but Lua does not receive a raw `payload`
byte array; text messages larger than 64 KiB and binary messages should be
handled through `payload_len`, `payload_fingerprint`, and `opcode`.

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

Inspect WebSocket text messages:

```lua
function on_websocket_message(event)
  if event.kind.opcode.kind ~= "text" then
    return nil
  end

  if event.kind.payload_len > 65536 then
    return probe.emit_alert("large text websocket message")
  end

  if event.kind.payload_text ~= nil and
      string.find(event.kind.payload_text, "token=", 1, true) then
    return probe.emit_alert("websocket message contains token material")
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
runtime_error_disable_threshold = 3

[policies.source]
kind = "local_directory"
path = "/etc/probe/policies/http-guard"
```

Reference a remote bundle:

```toml
[[policies]]
id = "http-guard"
enabled = true
runtime_error_disable_threshold = 3

[policies.source]
kind = "remote_bundle"
endpoint = "https://policy.example/bundles/http-guard.toml"
max_body_bytes = 16777216
```

Remote policy endpoints must be HTTPS, except loopback HTTP endpoints used for
local testing. Credentials in URLs are rejected.

The endpoint response body is one TOML document. The `source` field carries the
Lua source that would otherwise be stored in `main.lua`; the `[manifest]` table
uses the same schema as a local `manifest.toml`. Bundle-local modules are carried
as `[[modules]]` entries with `name` and `source`. Unknown top-level, manifest,
or module fields are rejected.

`runtime_error_disable_threshold` is evaluated per policy. A Lua runtime error
advances the consecutive error counter after its `policy_runtime_error` audit
event is written to the export queue. A successful hook execution resets the
counter; selector misses do not affect it. Reaching the threshold disables only
that policy, and online admin status reports the disabled policy and reason.
Use `0` to keep exporting errors without automatic disablement.

```toml
source = '''
local format = require("guard.format")

function on_http_request_headers(event)
  return probe.emit_alert(format.alert(event))
end
'''

[manifest]
id = "http-guard"
version = "2026-06-30"
hooks = ["on_http_request_headers"]
modules = ["guard.format"]

[[modules]]
name = "guard.format"
source = '''
local M = {}

function M.alert(event)
  return "HTTP " .. event.kind.method .. " " .. event.kind.target
end

return M
'''
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
