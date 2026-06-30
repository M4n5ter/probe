# HTTP Endpoint 契约

Probe 会把 HTTP endpoint 用于 export、remote policy input 和本机 proxy-side hook。
不同字段的安全契约不同；按字段名选择对应规则。

## Export Webhook

字段：`exporters.<id>.endpoint`

允许的 URL：

- absolute `http://` 或 `https://` URL；
- 必须包含 scheme 和 host；
- URL credentials 会被拒绝。

认证应使用显式 exporter headers 或 TLS material refs。配置 exporter TLS material 时，
endpoint 必须使用 `https://`。

request 和 acknowledgement contract 见
[webhook-receiver_ZH.md](webhook-receiver_ZH.md)。

## Remote Policy Bundle

字段：`policies.source.endpoint`

允许的 URL：

- 非本地 endpoint 使用 `https://`；
- 本地测试可使用 loopback `http://`；
- URL credentials 会被拒绝。

response body 受 `max_body_bytes` 限制。

## Remote Enforcement Manifest

字段：`enforcement.policy.source.endpoint`

允许的 URL：

- 非本地 endpoint 使用 `https://`；
- 本地测试可使用 loopback `http://`；
- URL credentials 会被拒绝。

response body 受 `max_body_bytes` 限制。

## MITM Policy Hook

字段：`enforcement.interception.mitm.policy_hook.endpoint`

允许的 URL：

- loopback IP `http://` URL；
- 必须显式配置非零端口；
- URL credentials 和 fragment 会被拒绝；
- host 必须是 `127.0.0.1` 或 `[::1]` 这样的 IP 地址。

`http://localhost:15002/...` 会被拒绝，因为 hook contract 要求 loopback IP address，
而不是 hostname。
