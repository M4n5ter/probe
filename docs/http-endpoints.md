# HTTP Endpoint Contracts

Probe uses HTTP endpoints for export, remote policy inputs, and local proxy-side
hooks. Each field has a different security contract; use the field name to pick
the correct rule.

## Export Webhook

Field: `exporters.<id>.endpoint`

Allowed URL:

- absolute `http://` or `https://` URL;
- scheme and host are required;
- URL credentials are rejected.

Authentication should use explicit exporter headers or TLS material refs. When
exporter TLS material is configured, the endpoint must use `https://`.

The request and acknowledgement contract is documented in
[webhook-receiver.md](webhook-receiver.md).

Examples:

| URL | Result |
| --- | --- |
| `https://collector.example/probe/batches` | Accepted. |
| `http://127.0.0.1:9000/batches` | Accepted for local or private deployments. |
| `https://user:pass@collector.example/probe/batches` | Rejected because URL credentials are not allowed. |

## Remote Policy Bundle

Field: `policies.source.endpoint`

Allowed URL:

- `https://` for non-local endpoints;
- loopback `http://` for local testing;
- URL credentials are rejected.

The response body is bounded by `max_body_bytes`.

Examples:

| URL | Result |
| --- | --- |
| `https://policy.example/bundles/http-guard.toml` | Accepted. |
| `http://127.0.0.1:9000/http-guard.toml` | Accepted for local testing. |
| `http://policy.example/bundles/http-guard.toml` | Rejected for non-local transport. |

## Remote Enforcement Manifest

Field: `enforcement.policy.source.endpoint`

Allowed URL:

- `https://` for non-local endpoints;
- loopback `http://` for local testing;
- URL credentials are rejected.

The response body is bounded by `max_body_bytes`.

Examples:

| URL | Result |
| --- | --- |
| `https://policy.example/probe/enforcement.toml` | Accepted. |
| `http://127.0.0.1:9000/enforcement.toml` | Accepted for local testing. |
| `https://user:pass@policy.example/probe/enforcement.toml` | Rejected because URL credentials are not allowed. |

## MITM Policy Hook

Field: `enforcement.interception.mitm.policy_hook.endpoint`

Allowed URL:

- loopback IP `http://` URL;
- explicit non-zero port is required;
- URL credentials and fragments are rejected;
- host must be an IP address such as `127.0.0.1` or `[::1]`.

`http://localhost:15002/...` is rejected because the hook contract requires a
loopback IP address, not a hostname.

Examples:

| URL | Result |
| --- | --- |
| `http://127.0.0.1:15002/mitm-policy-hook` | Accepted. |
| `http://[::1]:15002/mitm-policy-hook` | Accepted. |
| `http://localhost:15002/mitm-policy-hook` | Rejected because the host is not an IP address. |
| `https://127.0.0.1:15002/mitm-policy-hook` | Rejected because the hook uses loopback HTTP. |
