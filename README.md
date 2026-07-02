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
  use webhook, Unix HTTP sidecar, or file sinks with `none`, `zstd`, `gzip`,
  or `deflate` compression.
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

Install the eBPF build toolchain used by the default agent build:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
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

Run the single-machine validation path without special privileges:

```bash
cargo run -p xtask --locked -- validate-local
```

Run the non-privileged E2E baseline:

```bash
cargo run -p xtask --locked -- e2e-suite --profile baseline \
  --report-json target/probe-e2e/baseline.json
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
- nightly Rust with `rust-src` and `bpf-linker`; the agent embeds first-party
  process-observation and TLS uprobe objects by default during build.

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

Build eBPF artifacts when developing or validating custom eBPF objects:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo run -p xtask --locked -- ebpf-build
```

The agent embeds the first-party process-observation and TLS uprobe objects by
default when it is built. At runtime it materializes the required embedded
objects under `PROBE_HOME/artifacts/ebpf`. Set `capture.ebpf.object_path` or
`tls.plaintext.instrumentation.libssl_uprobe_object_path` only when using a
custom or externally managed eBPF object.

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
  eBPF object. Deep observation is selector-gated; syscall payload bytes are
  degraded evidence, and available `sendfile(2)`/`sendfile64(2)` tracepoint
  variants produce byte-count gaps rather than payload bytes. Runtime status
  reports which optional syscall variants the running kernel exposes.
- libssl uprobe:
  best-effort TLS plaintext sidecar for selected libssl processes. It needs
  root/bpffs, an embedded or configured TLS uprobe object, and an explicit
  selector.
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

### Server-Local TUI

Use the TUI when operating directly on a Linux host:

```bash
cargo run -p agent --locked -- tui
```

The TUI is a config workbench for common server operations. It reads `/proc`
through the same procfs attribution model used by the agent and shows readable
processes. Keyboard and mouse are equal interaction modes: every common action
is modeled once and exposed through both key bindings and rendered hit targets.
Process scopes are written only when the process has a readable executable path;
argv is not retained by the TUI model, and the process table shows only a
redacted argv count. The Processes tab supports keyboard and mouse browsing plus
process search. Use `/`, `Ctrl-F`, or `[Search]` to filter by PID, process
name, or executable path; `[Clear]` removes the filter. Save takes an advisory
lock, refuses stale files, validates the rendered config, and uses an atomic
same-directory write. The config path must be a direct file path; symlink paths
are rejected so save never replaces a link with a regular file.

The workbench can add a default exporter, switch exporter transport, edit
webhook endpoints, file paths, Unix HTTP socket paths, exporter compression,
export worker state, storage retention record limits, capture backend selection,
admin socket enablement and path, Prometheus listener enablement, enforcement
mode/backend, transparent interception strategy, TLS plaintext hook enablement,
and process-scoped selectors for capture, enforcement,
interception, and TLS plaintext. Policy Lua source, large MITM backend
contracts, TLS material files, exporter headers/TLS material refs, and
collector-specific payload formats should still be edited in the config and
policy files.

Without `--config`, the TUI uses `PROBE_HOME/config/agent.toml` and creates a
minimal safe config if the file does not exist. The generated admin socket path
is `PROBE_HOME/run/admin.sock`, but the generated config keeps admin disabled.
Pass `--config ./agent.toml` when editing an explicit file.

On startup, the TUI probes the configured admin socket. If a running agent
responds, the TUI reuses it. Otherwise, the TUI starts a managed local agent
from the same binary and stops that child process when the TUI exits. The
managed child uses a TUI-owned runtime overlay under `PROBE_HOME/run/tui/`;
that overlay enables a private admin socket and writes stdout/stderr to
`agent.log`. The user's config is not mutated just because the TUI needs a
runtime admin socket. If managed startup fails, the TUI error includes the log
path and a short tail so the real agent startup error is visible.

The Traffic tab tails parsed export events from the active agent admin surface.
It uses the selected process executable-path selector when available; if the
selected process has no readable executable path, traffic filtering fails closed
instead of showing unrelated host traffic. The TUI keeps only display summaries
for the event table and does not retain raw process argv.

The Runtime tab can call the online admin `reload_runtime_actions` command. It
reloads the runtime owners that are explicitly safe to update online, currently
policy bundles and the external enforcement manifest, and reports partial
failures per action. It does not replace the active main agent config; use it
after saving policy or enforcement inputs that are already referenced by the
running config. The same tab edits admin socket settings for future runs; the
current TUI session keeps using the active socket it attached to at startup.

### Minimal Policy And Webhook Wiring

Use this section when wiring the first real integration. A deployable setup
must state four contracts explicitly: where events come from, where durable
state is stored, which Lua hooks inspect typed events, and how the collector
acknowledges export batches. Probe does not infer these contracts from endpoint
names or policy filenames.

`PROBE_HOME` is the local state root used by config defaults and TUI-generated
paths. By default it follows the user state directory:
`$XDG_STATE_HOME/traffic-probe`, or `$HOME/.local/state/traffic-probe` when
`XDG_STATE_HOME` is not set. Set it explicitly before creating or editing a
config when local state should live elsewhere:

```bash
export PROBE_HOME="/var/lib/traffic-probe"
```

Explicit TOML paths are used as written and are not expanded. In a restricted
environment with no usable user home, Probe falls back to `/var/lib/traffic-probe`.

Uninstalling Probe should be boring: stop any running service, remove the
binary or package using the method that installed it, then remove the local
state tree generated by Probe:

```bash
# Default user-local state.
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/traffic-probe"

# Machine-level service state when PROBE_HOME was set this way.
sudo rm -rf /var/lib/traffic-probe
```

If a deployment used a custom `PROBE_HOME`, remove that directory instead.
External config, policy, certificate, and systemd unit paths are operator-owned
and should be removed according to the deployment's install layout.

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
- WebSocket text messages up to 64 KiB expose `event.kind.payload_text`;
  larger text messages and binary messages expose length and fingerprint
  without expanding payload bytes into a Lua table.
- A hook may return `nil`, one outcome, or an array of outcomes.
- `probe.emit_alert(message)` creates audit telemetry.
- `probe.verdict { ... }` requests a protective action. It becomes destructive
  only when enforcement mode, selector, backend, and policy allow it.
- The sandbox keeps policy code bounded. `table`, `string`, `math`, and `bit`
  are available; `require` can load only declared bundle-local modules; host
  APIs such as `io`, `os`, `debug`, `ffi`, and `loadfile` are unavailable.
- `runtime_error_disable_threshold` is per policy. A Lua runtime error advances
  the consecutive error counter after its `policy_runtime_error` audit event is
  written to the export queue. A successful hook execution resets the counter;
  selector misses do not affect it. When the threshold is reached, the agent
  disables only that policy and online admin status reports the disabled policy
  and reason. Set the threshold to `0` to keep auditing errors without automatic
  disablement.

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
# Optional override for a custom process-observation object. Normal runs use
# the embedded object materialized under PROBE_HOME/artifacts/ebpf.
# object_path = "/opt/traffic-probe/ebpf-process-observation.bpf.o"

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
path = "/var/lib/traffic-probe/plaintext-feed.jsonl"
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
path = "/var/lib/traffic-probe/capture-events.jsonl"
follow = true
```

### Storage

Live runs and exporter cursors need a Fjall spool:

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

Ingress recovery replays persisted capture events before opening a new capture
provider. Active parser state is not serialized, so recovery is conservative and
reported as degraded in the capability model.
Exporter ACKs advance per-sink cursors only; physical export queue deletion is
controlled by `storage.retention.export`.

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

Each export batch is bounded by both record count and stored payload bytes:
up to 1024 records and a 16 MiB payload-byte soft limit. A single larger event
is still sent alone so the sink cursor can keep moving.

Supported codecs are `none`, `zstd`, `gzip`, and `deflate`; `zstd` is the
default. Webhook sinks can reference trust anchors and client identities from
`[[tls.materials]]`. File sinks create private `0600` files and reject unsafe
parent directories. Unix HTTP sinks send the same protobuf batch and ACK
protocol over a local Unix domain socket, which is useful for a server-local
collector sidecar without opening a TCP listener.

#### Webhook Receiver Setup

The first integration section shows the webhook request, ACK, and retry
contract. The full receiver reference is in
[docs/webhook-receiver.md](docs/webhook-receiver.md), the batch schema is in
[docs/export-batch.proto](docs/export-batch.proto), and endpoint rules for all
HTTP surfaces are in [docs/http-endpoints.md](docs/http-endpoints.md).

### Policy

`agent run` uses policy bundles: a local bundle is a directory with
`manifest.toml`, `main.lua`, and optional declared bundle-local modules, as
shown in the first integration section.

Remote policy bundles are configured as bounded TOML documents; the response
schema, module format, and example are in
[docs/lua-policy.md](docs/lua-policy.md):

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

`agent replay --policy` is intentionally different: it accepts one Lua file for
local debugging and wraps it in a synthetic replay manifest.

The full hook table, event field reference, sandbox contract, outcome model, and
practical Lua patterns are documented in [docs/lua-policy.md](docs/lua-policy.md).

### TLS Material

TLS material references are shared by exporters, TLS decrypt hints, and MITM:

```toml
[tls.material_store.filesystem]
allowed_roots = ["/etc/probe/certs", "/var/lib/traffic-probe/tls"]

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

TLS material files must be owned by the effective uid of the process that reads
them, must be regular files, must be owner-readable, and must not grant group or
other permissions.
Use `0600` for writable private material and `0400` for read-only material.
When `allowed_roots` is non-empty, every TLS material path must be absolute and
must resolve beneath one configured root. The Linux store opens material through
`openat2` with beneath and no-symlink resolution flags, so `..` traversal and
symlink escapes fail closed. An empty root list keeps the filesystem store
unrestricted apart from the file type, size, ownership, and permission checks.
When the agent launches the first-party MITM proxy, the same roots are passed to
that proxy, and the proxy applies the same file type, size, ownership, and
permission checks for TLS termination and upstream trust material loading.

Best-effort libssl plaintext instrumentation is explicit. Agent builds embed
the first-party TLS uprobe object by default, alongside the process-observation
object used by eBPF capture. When hooks are enabled and no override path is
configured, the agent materializes the TLS object under
`PROBE_HOME/artifacts/ebpf/` and uses the generated content-addressed path.
Configure a selector to avoid broad attachment:

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
cgroup_paths = []

[tls.plaintext.instrumentation.selector.term.traffic]
local_ports = []
remote_ports = [443]
directions = ["outbound"]
remote_addresses = []
```

`capture.ebpf.object_path` and `libssl_uprobe_object_path` are advanced
overrides for custom eBPF artifacts. Normal installations should keep generated
assets under `PROBE_HOME` so uninstalling the probe can remove a single state
tree.

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

When passive eBPF/libpcap capture is unavailable, transparent proxy or MITM can
provide a reliable plain HTTP and TLS-decrypted HTTP content path for scoped
traffic. This is an explicit data-plane strategy: traffic steering,
operator-managed trust, a MITM backend, and a `capture_event_feed` plaintext
bridge must be configured. With that bridge configured,
`capture.selection = "auto"` can use the MITM feed after passive capture
candidates fail.

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
cgroup_paths = []

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
cgroup_paths = []

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

`cgroup_paths` are cgroup v2 path prefixes relative to `/sys/fs/cgroup`;
leading `/` is accepted. A selector path matches that cgroup and its
descendants. Outbound transparent interception can project UID/GID-only and
cgroup-path-only process selectors into nft socket rules before proxy relay.
The nft `socket cgroupv2` rule is a static install-time boundary: the cgroup
path must exist when nft validates the ruleset, and recreated cgroups need a
ruleset refresh or a dynamic classifier/lifecycle watcher.

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
cgroup_paths = []

[enforcement.interception.selector.term.traffic]
local_ports = []
remote_ports = [443]
directions = ["outbound"]
remote_addresses = []
```

Linux socket destroy closes existing TCP sockets only. It uses
`NETLINK_SOCK_DIAG` with `SOCK_DESTROY`, verified by an active loopback
self-test before the capability is reported as available. It is not pre-connect
deny, UDP blocking, or payload-level blocking. Successful destroys emit typed
`connection_backend/linux_socket_destroy` mechanism evidence in the exported
`EnforcementDecision`; the top-level `effective_action` carries the policy
action accepted by the planner. Admin metrics expose
`metrics.pipeline.enforcement.execution.connection_backend.linux_socket_destroy`
so operators can distinguish decision outcomes from the backend surface that
actually ran.

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
cgroup_paths = []

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
path = "/var/lib/traffic-probe/mitm/feed.jsonl"
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
state. `reload-runtime-actions` runs every runtime action that is safe under the
active `RuntimePlan` and reports each outcome independently, so a failed
enforcement reload does not hide a successful policy reload. The CLI exits
non-zero when any action outcome is `failed` after printing the full JSON
response. Candidate main configs can also be parsed and statically validated,
then reported as
`no_change`, `restart_required`, or `invalid_candidate`; this is a planning
surface, not live owner replacement for capture, export, TLS, admin, or
interception resources, and it does not run setup-time active probes. Candidate
config reads require a regular file, reject symlinks and oversized files, and do
not echo raw config lines in parse errors.

The Prometheus listener is read-only, loopback-only, and serves only
`GET /metrics`; control commands stay on the private Unix socket. Runtime status
and metrics include capture input activity, pipeline progress, spool/export
state, policy/enforcement counters, TLS plaintext activity, and proxy health.
Enforcement metrics include outcome counters and execution-surface counters for
Linux socket destroy and L7 MITM proxy hooks. Prometheus exposes the same facts
through `traffic_probe_pipeline_enforcement_decisions_total` and
`traffic_probe_pipeline_enforcement_execution_total`.
Capture input activity includes the latest signal kind, sequence, and
observation time without treating that activity as kernel link liveness. The
eBPF provider status separately reports held tracepoint links, explicit kernel
liveness proof status, and optional kernel tracepoint-pair availability, such as
`sendfile` or `sendfile64`.
The admin CLI sends the same JSON-lines commands over the Unix socket. When
`--socket` is omitted, it uses `PROBE_HOME/run/admin.sock`. Service
deployments that configure `/run/traffic-probe/admin.sock` should pass that
path explicitly.

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
  debug-dump
```

`tail-events` is a bounded, non-mutating view over the durable export queue. It
returns complete event envelopes for automation and advances only the response
cursor (`next_after_sequence`); it does not acknowledge exporter sink cursors.
It can only read records still retained by `storage.retention.export`. Large
records are omitted with explicit omission metadata rather than expanded without
a byte budget.
`debug-dump` reuses the online status snapshot and adds admin protocol metadata.
It includes runtime plan/status fields and local paths, but not raw config text
or secret material bytes.

Local watching and remote polling are opt-in. Use local triggers for local
sources:

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

- `baseline` runs as a normal user and covers local validation, replay,
  plaintext feed, gap/loss events, HTTP/SSE/WebSocket, webhook/file/Unix HTTP
  export, one-shot plus polled remote policy inputs, and first-party product
  MITM proxy plaintext/TLS feed ingestion without transparent host rules.
- `live-core` needs root or CAP_NET_RAW and covers libpcap loopback, single and
  composite admin reload, socket destroy, and TLS key log/session-secret
  material.
- `process-ebpf` needs root/bpffs and covers eBPF process observation plus
  real process ring-buffer output loss.
- `tls-plaintext` needs root/bpffs and covers the libssl plaintext provider
  attach lifecycle, and real TLS plaintext ring-buffer output loss.
- `transparent-interception` needs root/net-admin and covers inbound TPROXY,
  outbound proxy, MITM plaintext bridge, policy hook, and product proxy
  HTTPS/WebSocket paths.
- `linux-artifacts` needs root/net-admin and covers Linux transparent
  interception artifact acceptance, including socket-cgroup outbound rules when
  a non-root cgroup v2 path and nft socket-cgroup resolver are available.
- `product` combines the user, live, eBPF, TLS, interception, MITM, and Linux
  artifact suites.

List cases, profiles, and machine-readable coverage:

```bash
cargo run -p xtask --locked -- e2e-suite --list
cargo run -p xtask --locked -- e2e-suite --list-profiles
cargo run -p xtask --locked -- e2e-suite --inventory-json
```

`--list` prints each case with its privilege requirement and capability IDs.
`--list-profiles` prints each profile with its requirement set, capability
union, description, and expanded case list. `--inventory-json` exposes schema
version 2 from the same registry: capability catalog entries include category
metadata, and per-case plus per-profile coverage are derived from one source.
Use `--report-json <path>` on a suite run to persist the actual run result,
including each selected case, status, duration, requirement, and capability IDs.
The run report is schema version 1 and has this stable shape:

| Field | Meaning |
| --- | --- |
| `schema_version` | Report schema version. |
| `selection` | Requested suite selection, including `kind`, optional `profile`, and explicit case names for `cases` selections. |
| `summary` | Suite status, total case count, status counters, and `duration_ms`. |
| `cases[]` | Case metadata from the registry plus run `status`, `duration_ms`, and optional `skip_reason`. |

`selection.kind` is `default_profile`, `include_privileged`,
`only_privileged`, `cases`, or `profile`. Suite status is `passed`,
`completed_with_skips`, or `failed`. Case status is `passed`, `skipped`,
`failed`, or `not_run`; `skip_reason` appears only for skipped cases. Durations
are integer milliseconds.

Run the single-machine validation path:

```bash
cargo run -p xtask --locked -- validate-local
```

Run the non-privileged baseline:

```bash
cargo run -p xtask --locked -- e2e-suite --profile baseline \
  --report-json target/probe-e2e/baseline.json
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
