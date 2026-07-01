# Probe

[简体中文](README_ZH.md) · [Design](docs/design.md) ·
[Lua policy](docs/lua-policy.md) ·
[Webhook receiver](docs/webhook-receiver.md) ·
[HTTP endpoints](docs/http-endpoints.md) ·
[Safe default config](examples/agent.toml) · [Local demo config](examples/local-agent.toml)

Probe is a Linux process-level traffic probe for security telemetry, protocol
visibility, durable evidence, export, and controlled enforcement.

It observes traffic on a host, attributes it to processes and sockets, parses
protocol semantics, evaluates Lua policy, writes durable event evidence, and
exports structured batches. It is designed for servers where packet mirrors,
special hardware, service-mesh sidecars, or application SDKs are not the right
deployment model.

Probe is usable today in controlled Linux environments. It is not a turnkey
production appliance: privileged live capture, transparent interception, and
MITM require explicit host setup, operator-owned trust decisions, and capability
checks.

## What You Can Do Today

- Try the full parser/policy/spool/export loop without root:
  use `examples/local-agent.toml` with the plaintext feed and file exporter.
- Re-process captured bytes:
  use `agent replay` with a raw HTTP input file and optional Lua policy.
- Consume deterministic external input:
  use `capture.selection = "plaintext_feed"` or
  `capture.selection = "capture_event_feed"`.
- Capture live traffic:
  use libpcap with root/CAP_NET_RAW, or eBPF when the object path and host
  prerequisites are present.
- Inspect TLS traffic:
  use key log/session-secret material, libssl uprobe plaintext
  instrumentation, explicit plaintext bridges, or scoped MITM.
- Export events:
  use webhook or file sinks with `none`, `zstd`, `gzip`, or `deflate`
  compression.
- Apply policy:
  use local or remote Lua policy bundles for typed events and verdicts.
- Protect selected applications:
  use audit-only, dry-run, scoped TCP connection destroy, transparent
  interception, or MITM policy hooks.

The capability model is intentionally explicit. If a provider is unavailable or
evidence is degraded, `agent capabilities`, `agent check`, and `agent status`
say so instead of treating best-effort observation as complete.

## Quick Start

On Debian or Ubuntu hosts, install the native build dependency first:

```bash
sudo apt-get install -y libpcap-dev pkg-config
```

Build the main binaries:

```bash
cargo build -p agent -p xtask --locked
```

Inspect what this host can support:

```bash
cargo run -p agent --locked -- capabilities
```

Run the non-privileged local demo:

```bash
rm -rf target/probe-demo
mkdir -p target/probe-demo

cargo run -p agent --locked -- check --config examples/local-agent.toml
cargo run -p agent --locked -- run --config examples/local-agent.toml --max-events 3
wc -l target/probe-demo/export.jsonl
head -n 1 target/probe-demo/export.jsonl
```

That path reads [examples/plaintext-feed.jsonl](examples/plaintext-feed.jsonl),
loads [examples/policies/http-alert](examples/policies/http-alert), stores
events in `target/probe-demo/spool`, and appends one file-export batch to
`target/probe-demo/export.jsonl`.

The file exporter writes JSON Lines batch records. Each line carries metadata
plus a base64-encoded protobuf batch envelope, optionally compressed by the
configured codec. It is meant for collectors and tooling, not as a pretty event
log.

Replay raw HTTP bytes without live-capture privileges:

```bash
rm -rf target/probe-demo/replay-spool

cargo run -p agent --locked -- replay \
  --input examples/replay.http \
  --spool target/probe-demo/replay-spool \
  --policy examples/policies/http-alert/main.lua \
  --agent-id probe-replay-demo
```

Run the non-privileged E2E baseline:

```bash
cargo run -p xtask --locked -- e2e-suite --profile baseline
```

For real collector or policy rollout, start with [Minimal Policy And Webhook Wiring](#minimal-policy-and-webhook-wiring).

## Install Requirements

Common requirements:

- Linux with procfs;
- stable Rust with edition 2024 support;
- `libpcap` development headers and `pkg-config` for the default agent build;
- root or matching Linux capabilities for live capture, eBPF, socket destroy,
  transparent interception, or MITM tests;
- `nftables` package when running Linux transparent interception;
- nightly Rust with `rust-src` and `bpf-linker` only when building eBPF
  artifacts.

Common `nft` installation commands:

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

When `nft` is missing, the agent capability probe reads `/etc/os-release`
first, then probes common package managers on unknown distributions. The
reported command omits `sudo` when the probe itself is already running as root.

Build the first-party MITM proxy and fixture when running MITM E2E cases:

```bash
cargo build -p agent -p e2e-fixture -p mitm-proxy -p xtask --locked
```

Build eBPF artifacts:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo run -p xtask --locked -- ebpf-build
```

After building eBPF artifacts, set the generated object path in the agent
configuration:

- process observation: `capture.ebpf.object_path`;
- libssl plaintext instrumentation:
  `tls.plaintext.instrumentation.libssl_uprobe_object_path`.

## Choose A Run Mode

- `agent replay`:
  re-process one raw byte stream through parser, policy, spool, and optional
  webhook export. It needs no live-capture privilege.
- `plaintext_feed`:
  use file-readable JSONL for development, SDKs, tests, bridges, or trusted
  plaintext handoff.
- `capture_event_feed`:
  accept typed `CaptureEvent` JSONL from MITM bridges or external collectors.
  `follow = true` can keep the agent online.
- `libpcap`:
  live packet capture when eBPF is unavailable or not configured. It needs root
  or CAP_NET_RAW.
- `ebpf`:
  kernel-assisted process-aware observation. It needs root/bpffs and a built
  eBPF object.
- libssl uprobe:
  best-effort TLS plaintext sidecar for selected libssl processes. It needs
  root/bpffs, a built eBPF object, and an explicit selector.
- Transparent interception:
  scoped inbound/outbound steering before or around application traffic. It
  needs root/net-admin and explicit selectors.
- Product MITM proxy:
  scoped TLS termination, upstream relay, plaintext bridge, and proxy-side
  policy hook. It needs root/net-admin, certificate material, and
  operator-managed client trust.

## Configure Probe

Start from one of these files:

- [examples/local-agent.toml](examples/local-agent.toml) for a runnable local
  demo;
- [examples/agent.toml](examples/agent.toml) for a commented safe-default
  server template.

Validate a config before running it:

```bash
cargo run -p agent --locked -- check --config ./agent.toml
cargo run -p agent --locked -- status --config ./agent.toml
```

`check` validates the runtime plan and configured policy. `status` is a
side-effect-light status snapshot; it reports metadata for local policy bundles
but does not execute them.

### Minimal Policy And Webhook Wiring

Use this section when wiring the first real integration. A deployable setup
must state four contracts explicitly: where events come from, where durable
state is stored, which Lua hooks inspect typed events, and how the collector
acknowledges export batches. Probe does not infer these contracts from endpoint
names or policy filenames.

```text
/etc/probe/agent.toml
/etc/probe/policies/http-guard/manifest.toml
/etc/probe/policies/http-guard/main.lua
```

Start with deterministic input and an uncompressed webhook. Once the receiver
passes interop, switch `capture.selection` to the live backend and set
`codec = "zstd"` or another supported codec.

Agent config:

```toml
[capture]
selection = "plaintext_feed"

[capture.plaintext_feed]
path = "/var/lib/probe/plaintext-feed.jsonl"

[storage]
path = "/var/lib/probe/spool"

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

[policies.source]
kind = "local_directory"
path = "/etc/probe/policies/http-guard"

[enforcement]
mode = "audit_only"
backend = "none"
```

Policy manifest:

```toml
id = "http-guard"
version = "2026-06-30"
hooks = ["on_http_request_headers", "on_websocket_message"]
```

How Lua policy should be written:

- `agent run` loads a policy bundle directory, not a loose Lua file.
- `manifest.toml` names the hooks Probe may call; each named hook must exist as
  a global Lua function in `main.lua`.
- Each hook receives one typed `event` table. Common metadata is on `event`;
  protocol fields are on `event.kind`.
- A hook may return `nil`, one outcome, or an array of outcomes.
- `probe.emit_alert(message)` creates audit telemetry.
- `probe.verdict { ... }` requests a protective action. It becomes destructive
  only when enforcement mode, selector, backend, and policy allow it.
- The sandbox keeps policy code bounded. `table`, `string`, `math`, and `bit`
  are available; host APIs such as `io`, `os`, `require`, `debug`, `ffi`, and
  `loadfile` are unavailable.

Lua source:

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
  if event.kind.opcode.kind == "text" and event.kind.payload_len > 65536 then
    return probe.emit_alert("large websocket text message")
  end
end
```

Endpoint format requirements:

- Export webhook (`exporters.<id>.endpoint`):
  absolute `http://` or `https://` URL with a scheme and host, such as
  `https://collector.example/probe/batches` or
  `http://127.0.0.1:9000/batches` for local testing. URL credentials are
  rejected. Exporter TLS refs require `https://`.
- Remote Lua policy (`policies.source.endpoint`):
  `https://` for non-local endpoints, such as
  `https://policy.example/bundles/http-guard.toml`. Loopback `http://` is
  allowed only for local testing. URL credentials are rejected.
- Remote enforcement policy (`enforcement.policy.source.endpoint`):
  same transport rule as remote Lua policy bundles.
- MITM policy hook (`enforcement.interception.mitm.policy_hook.endpoint`):
  loopback IP `http://` URL with an explicit non-zero port, such as
  `http://127.0.0.1:15002/mitm-policy-hook`. Hostnames, credentials,
  fragments, missing ports, and `https://` are rejected.

Webhook receiver contract:

- Endpoint URL:
  absolute `http://` or `https://` URL with scheme and host. URL credentials
  are rejected. TLS refs require `https://`.
- Method:
  `POST` to the configured path and query.
- `content-type`:
  `application/x-protobuf`.
- `x-traffic-probe-codec`:
  `none`, `zstd`, `gzip`, or `deflate`; decode the body by this header.
- `idempotency-key`:
  the export batch id; use it for deduplication.
- Body:
  `BatchEnvelope` protobuf bytes, compressed according to
  `x-traffic-probe-codec`.
- ACK body:
  UTF-8 JSON no larger than 64 KiB.

ACK JSON:

```json
{
  "batch_id": "probe-local:primary-webhook:1-4",
  "accepted": true,
  "acked_cursor": 4,
  "reason": null
}
```

Return `accepted = true` only after the receiver durably stores every record up
to `acked_cursor`. Probe retries the batch when the status is non-2xx, the body
is not valid ACK JSON, `batch_id` does not match, `accepted = false`, or
`acked_cursor` is outside the request sequence range.

Receiver algorithm:

```text
verify POST, content-type, idempotency-key, and x-traffic-probe-codec
decode the body according to x-traffic-probe-codec
decode BatchEnvelope using docs/export-batch.proto
verify BatchEnvelope.batch_id matches idempotency-key
durably upsert records by batch_id and EventRecord.sequence
return accepted=true with the last contiguous durable sequence
```

For the first collector interop test, use `codec = "none"` or `--codec none`
so the receiver only needs protobuf decoding. Enable `zstd`, `gzip`, or
`deflate` after the receiver handles `x-traffic-probe-codec`.

`agent replay --policy` is a debugging entry point: it accepts one Lua file and
wraps it in a synthetic replay manifest. Use it to verify a receiver without
live-capture privileges:

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

Automatic live selection tries configured fallback backends in order:

```toml
[capture]
selection = "auto"
fallback_backends = ["ebpf", "libpcap"]

[capture.ebpf]
object_path = "target/ebpf/bpfel-unknown-none/release/ebpf-program"

[capture.libpcap]
interface = "any"
bpf_filter = "tcp"
snaplen = 65535
promisc = false
immediate_mode = true
read_timeout_ms = 1000
```

Plaintext feed mode is deterministic and does not require live capture:

```toml
[capture]
selection = "plaintext_feed"

[capture.plaintext_feed]
path = "/var/lib/probe/plaintext-feed.jsonl"
```

The plaintext feed is JSON Lines: one event per line. Each event repeats the
`connection` object so a feed can be appended or replayed without hidden
process state. A `bytes` event uses a numeric byte array, a direction, and a
stream offset:

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

`connection_opened`, `connection_closed`, and `gap` events use the same
connection shape. `gap` includes `expected_offset`, optional `next_offset`, and
`reason`.

Capture-event feed mode accepts typed capture events and can follow appended
records:

```toml
[capture]
selection = "capture_event_feed"

[capture.capture_event_feed]
path = "/var/lib/probe/capture-events.jsonl"
follow = true
```

### Storage

Live runs and exporter cursors need a Fjall spool:

```toml
[storage]
path = "/var/lib/traffic-probe/spool"

[storage.retention.ingress]
sweep_interval_ms = 1000
prune_batch_limit = 1024

[storage.retention.export]
sweep_interval_ms = 1000
prune_batch_limit = 1024
```

Ingress recovery replays persisted capture events before opening a new capture
provider. Active parser state is not serialized, so recovery is conservative and
reported as degraded in the capability model.

### Export

Enable the worker for long-running agents and configure one or more sinks:

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
path = "/var/lib/probe/export.jsonl"
codec = "zstd"

[[exporters]]
id = "primary-webhook"
transport = "webhook"
endpoint = "https://collector.example/probe/batches"
codec = "zstd"
headers = { x_probe_node = "probe-local" }
```

Supported codecs are `none`, `zstd`, `gzip`, and `deflate`; `zstd` is the
default. Webhook sinks can reference trust anchors and client identities from
`[[tls.materials]]`. File sinks create private `0600` files and reject unsafe
parent directories.

#### Webhook Receiver Setup

The first integration section shows the webhook request, ACK, and retry
contract. The full receiver reference is in
[docs/webhook-receiver.md](docs/webhook-receiver.md), the batch schema is in
[docs/export-batch.proto](docs/export-batch.proto), and endpoint rules for all
HTTP surfaces are in [docs/http-endpoints.md](docs/http-endpoints.md).

### Policy

`agent run` uses policy bundles: a local bundle is a directory with
`manifest.toml` and `main.lua`, as shown in the first integration section.

Remote policy bundles are configured as bounded TOML documents; the response
schema and example are in [docs/lua-policy.md](docs/lua-policy.md):

```toml
[[policies]]
id = "http-alert"
enabled = true

[policies.source]
kind = "remote_bundle"
endpoint = "https://policy.example/bundles/http-alert.toml"
max_body_bytes = 16777216
```

`agent replay --policy` is intentionally different: it accepts one Lua file for
local debugging and wraps it in a synthetic replay manifest.

The full hook table, event field reference, sandbox contract, outcome model, and
practical Lua patterns are documented in [docs/lua-policy.md](docs/lua-policy.md).

### TLS Material

TLS material references are shared by exporters, TLS decrypt hints, and MITM:

```toml
[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/etc/probe/certs/collector-ca.pem"

[[tls.materials]]
id = "browser-keylog"
kind = "key_log_file"
path = "/var/lib/probe/tls/browser.keys"

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

Best-effort libssl plaintext instrumentation is explicit. Configure a selector
to avoid broad attachment:

```toml
[tls.plaintext.instrumentation]
enabled = true
libssl_uprobe_object_path = "/opt/probe/ebpf-tls-plaintext"
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

### Enforcement And MITM

Enforcement starts in audit-only mode:

```toml
[enforcement]
mode = "audit_only"
backend = "none"
```

Use `dry_run` to exercise planner decisions without applying a destructive
backend. Use `enforce` only with an explicit backend, selector, policy source,
and operational approval.

Lua policies emit event-level alerts and verdict requests. Enforcement policy
manifests are a separate control input that defines which protective actions may
be applied and, optionally, which process/traffic selector can use them:

```toml
[enforcement.policy.source]
kind = "file"
path = "/etc/probe/enforcement.toml"
```

An enforcement manifest is TOML. A runnable template is available at
[`examples/enforcement.toml`](examples/enforcement.toml):

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

Supported source kinds are:

- `none`, which disables configured enforcement policy input and is not valid
  with `mode = "enforce"`;
- `file`, where `path` points directly to one manifest;
- `directory`, where `path` points to a directory containing `manifest.toml`;
- `remote`, where `endpoint` returns one bounded TOML manifest and optional
  `max_body_bytes` caps the response body.

Remote endpoints must be absolute URLs without credentials. HTTPS is required
except for loopback HTTP endpoints used in local testing.

`protective_actions` accepts only `deny`, `reset`, and `quarantine`. This keeps
the destructive action profile explicit and separate from Lua event policy
logic.

Named selectors can be declared once and referenced from capture, TLS,
policy, enforcement, and transparent interception selectors:

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

Enforcement manifests may also declare their own `[selectors.<name>]` registry.
Manifest refs are resolved inside the manifest namespace before the agent
combines them with the main config selector.

Selector list fields default to empty lists when omitted. Empty process or
traffic dimensions mean "do not constrain this dimension"; they are not parse
errors.

Selectors combine process and traffic dimensions:

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

Linux socket destroy closes existing TCP sockets only. It uses
`NETLINK_SOCK_DIAG` with `SOCK_DESTROY`, verified by an active loopback
self-test before the capability is reported as available. It is not pre-connect
deny, UDP blocking, or payload-level blocking.

Transparent MITM is a separate strategy. It requires root/net-admin,
operator-managed client trust, certificate material refs, proxy listener
settings, backend readiness, plaintext bridge configuration, and a scoped
selector. The fragment below assumes the TLS material refs above are configured:

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

[enforcement.interception.mitm.backend.process]
program = "/usr/local/bin/traffic-probe-mitm-proxy"

[[enforcement.interception.mitm.backend.process.upstream_routes]]
host = "service.example.com"
target = "127.0.0.1:18443"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15001"

[enforcement.interception.mitm.plaintext_bridge]
mode = "capture_event_feed"
path = "/var/lib/probe/mitm-feed.jsonl"
follow = true

[enforcement.interception.mitm.policy_hook]
mode = "http_json"
endpoint = "http://127.0.0.1:15002/mitm-policy-hook"
```

The first-party product proxy supports exact and suffix-wildcard upstream
routes. Opt-in DNS discovery can be used as a fallback and rejects IANA
special-purpose/special-use addresses by default unless explicitly allowed.
CA-backed dynamic certificate mode requires downstream clients to send DNS SNI.
Host/SNI mismatches fail closed.

### Admin And Status

Enable the admin socket when online reloads are needed:

```toml
[admin]
enabled = true
socket_path = "/run/traffic-probe/admin.sock"

[admin.prometheus]
enabled = true
listen_addr = "127.0.0.1:9464"
```

Admin reloads validate new policy or enforcement state before swapping runtime
state. The Prometheus listener is read-only, loopback-only, and serves only
`GET /metrics`; control commands stay on the private Unix socket. Runtime
status and metrics include capture input activity, pipeline
progress, spool/export state, policy/enforcement counters, TLS plaintext
activity, and proxy health. Capture input activity includes the latest signal
kind, sequence, and observation time without treating that activity as kernel
link liveness. Local watching and remote polling are opt-in. Use local triggers
for local sources:

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

Use remote polling for remote sources:

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

Remote polling reloads the currently configured remote source on a fixed
interval. Policy polling validates unchanged bundles but does not replace the
active Lua VM when content is unchanged. A failed load keeps the previous active
policy or enforcement manifest.

## Operational Commands

```bash
agent capabilities
agent check --config ./agent.toml
agent status --config ./agent.toml
agent run --config ./agent.toml
agent replay --input ./traffic.http --spool ./spool --policy ./policy.lua
```

`capabilities`, `check`, and `status` return JSON for automation. When runtime
validation fails, `check` prints an `invalid_config` JSON report with violations
and the capability matrix, then exits non-zero. `run` starts the configured
agent. `replay` sends one byte stream through the same parser, policy, spool,
and optional webhook path without live-capture privileges.

## Verification

E2E profiles are organized around capability claims:

- `baseline` runs as a normal user and covers replay, plaintext feed,
  gap/loss events, HTTP/SSE/WebSocket, webhook/file export, and one-shot plus
  polled remote policy inputs.
- `live-core` needs root or CAP_NET_RAW and covers libpcap loopback, admin
  reload, socket destroy, and TLS key log/session-secret material.
- `process-ebpf` needs root/bpffs and covers eBPF process observation plus
  real process ring-buffer output loss.
- `tls-plaintext` needs root/bpffs and covers the libssl plaintext provider
  attach lifecycle, and real TLS plaintext ring-buffer output loss.
- `transparent-interception` needs root/net-admin and covers inbound TPROXY,
  outbound proxy, MITM plaintext bridge, policy hook, and product proxy
  HTTPS/WebSocket paths.
- `linux-artifacts` needs root/net-admin and covers Linux transparent
  interception artifact acceptance.
- `product` combines the user, live, eBPF, TLS, interception, MITM, and Linux
  artifact suites.

List cases and profiles:

```bash
cargo run -p xtask --locked -- e2e-suite --list
cargo run -p xtask --locked -- e2e-suite --list-profiles
```

Run the non-privileged baseline:

```bash
cargo run -p xtask --locked -- e2e-suite --profile baseline
```

Run privileged profiles in an isolated development environment:

```bash
sudo target/debug/xtask e2e-suite --profile live-core
sudo target/debug/xtask e2e-suite --profile process-ebpf
sudo target/debug/xtask e2e-suite --profile tls-plaintext
sudo target/debug/xtask e2e-suite --profile transparent-interception
```

Privileged cases may manipulate network namespaces, bpffs, nftables, policy
routing, or live sockets.

## Boundaries

Probe does not claim these capabilities:

- default whole-host transparent MITM;
- automatic client trust store mutation;
- HTTP/2, HTTP/3, or QUIC parsing;
- strong original attribution for every MITM path;
- a non-HTTP transparent allow-path matrix beyond covered WebSocket tunnel
  behavior;
- pre-connect deny, UDP blocking, or payload-level blocking through Linux socket
  destroy;
- hidden long-term raw traffic retention;
- complete best-effort live capture when the runtime reports degraded evidence.

The detailed design source, capability facts, and verification matrix are in
[docs/design.md](docs/design.md).

## Repository Layout

| Path | Responsibility |
| --- | --- |
| `crates/core` | event contracts, selectors, process/flow identity, verdicts, capability model |
| `crates/config` | TOML configuration model and validation |
| `crates/runtime` | runtime plan and capability validation |
| `crates/capture` | capture providers, eBPF/libpcap paths, TLS plaintext bridge |
| `crates/parsers` | parser traits and HTTP/SSE/WebSocket implementations |
| `crates/policy` | Lua policy runtime and event views |
| `crates/enforcement` | scoped enforcement planner and backend/hook contracts |
| `crates/pipeline` | capture-to-parser-to-policy-to-spool execution |
| `crates/agent` | runtime composition, config loading, status/admin surfaces |
| `crates/storage` | Fjall durable spool and cursor-backed queues |
| `crates/exporter` | export batches, codecs, webhook transport, file transport |
| `crates/mitm-proxy` | first-party L7 MITM product proxy |
| `crates/transparent-linux` | Linux transparent interception artifact planning |
| `crates/xtask` | end-to-end validation harness |
| `examples` | runnable demo inputs and commented config templates |

## Contributing

High-value contributions improve one of these properties:

- stronger process or socket attribution;
- clearer capability and degradation reporting;
- safer enforcement boundaries;
- protocol coverage through the existing parser traits;
- durable export transports;
- high-signal E2E coverage.

Before opening a change:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test --workspace --locked
```

## License

Probe is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
