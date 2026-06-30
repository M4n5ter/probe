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

## Remote Policy Bundle

Field: `policies.source.endpoint`

Allowed URL:

- `https://` for non-local endpoints;
- loopback `http://` for local testing;
- URL credentials are rejected.

The response body is bounded by `max_body_bytes`.

## Remote Enforcement Manifest

Field: `enforcement.policy.source.endpoint`

Allowed URL:

- `https://` for non-local endpoints;
- loopback `http://` for local testing;
- URL credentials are rejected.

The response body is bounded by `max_body_bytes`.

## MITM Policy Hook

Field: `enforcement.interception.mitm.policy_hook.endpoint`

Allowed URL:

- loopback IP `http://` URL;
- explicit non-zero port is required;
- URL credentials and fragments are rejected;
- host must be an IP address such as `127.0.0.1` or `[::1]`.

`http://localhost:15002/...` is rejected because the hook contract requires a
loopback IP address, not a hostname.
