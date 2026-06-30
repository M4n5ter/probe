# Webhook Receiver 参考

Probe webhook exporter 会把 durable export batch 发送到 HTTP endpoint。传输语义是
at-least-once：receiver 必须把 `batch_id` 或 `idempotency-key` 当作幂等键，并且只在 durable
ingestion 完成后提交 cursor。

## Endpoint 规则

webhook exporter 使用 `exporters.<id>.endpoint`。它必须是带 host 的 absolute
`http://` 或 `https://` URL，URL credentials 会被拒绝。配置 TLS material refs 时必须使用
`https://`。

其它 HTTP endpoint 字段有不同安全规则。endpoint matrix 见
[http-endpoints_ZH.md](http-endpoints_ZH.md)。

自定义 exporter headers 可用于部署 metadata，但以下协议头是保留字段，不能覆盖：

- `content-type`
- `idempotency-key`
- `x-traffic-probe-codec`

## Request

Probe 每个 export batch 发送一个 HTTP request：

| 部分 | 值 |
| --- | --- |
| Method | `POST` |
| Target | 配置的 endpoint path 和 query |
| `content-type` | `application/x-protobuf` |
| `x-traffic-probe-codec` | `none`、`zstd`、`gzip` 或 `deflate` |
| `idempotency-key` | batch id |
| Body | `BatchEnvelope` protobuf message，并按 codec header 压缩 |

手工维护的 wire schema 发布在 [export-batch.proto](export-batch.proto)。当前 Rust
实现位于 `crates/proto/src/batch.rs`；`published_export_batch_proto_matches_wire_contract`
会检查发布 schema 文本和一个代表性 protobuf byte encoding 是否与手写 `prost::Message`
model 一致。

当 `payload_format = PAYLOAD_FORMAT_JSON` 时，每个 `EventRecord.payload` 都是 JSON
`EventEnvelope`。payload schema 字符串是
`traffic.probe.event_envelope.subject_origin.json`。

## Compression

receiver 根据 `x-traffic-probe-codec` header 解码 request body：

| Codec | 含义 |
| --- | --- |
| `none` | body 是原始 protobuf bytes。 |
| `zstd` | body 是 Zstandard 压缩后的 protobuf bytes。 |
| `gzip` | body 是 gzip 压缩后的 protobuf bytes。 |
| `deflate` | body 是 zlib/deflate 压缩后的 protobuf bytes。 |

receiver 应拒绝未知 codec，不要猜测。`BatchEnvelope.codec` 字段会镜像配置的 exporter codec；
transport 契约以 header 为准。

## Acknowledgement

response body 必须是 UTF-8 JSON，并且不超过 64 KiB：

```json
{
  "batch_id": "probe-local:primary-webhook:1-4",
  "accepted": true,
  "acked_cursor": 4,
  "reason": null
}
```

- `batch_id`：
  必需。必须匹配 request batch id。
- `accepted`：
  必需。只有 receiver 已 durable accept 被确认前缀时才能返回 `true`。
- `acked_cursor`：
  `accepted = true` 时必需。它是 receiver 已提交的 export sequence cursor，
  且必须落在 request batch sequence 范围内。
- `reason`：
  可选，用于 rejection 或诊断原因。

未知 JSON 字段会被忽略，因此 receiver 可以附带本地 metadata。

如果完整消费 batch，`acked_cursor` 应设置为 batch 内最大的 `sequence`。如果只完成了部分
durable commit，则设置为最后一个连续 committed sequence。Probe 会把该 sink cursor 推进到这个值，
并按 export worker schedule 重试后续 record。

以下情况会让 sink 保持 unacked，并触发后续重试：

- 非 2xx HTTP status；
- response body 超过 64 KiB；
- response body 不是合法 JSON；
- `batch_id` mismatch；
- `accepted = false`；
- accepted response 缺少 `acked_cursor`；
- `acked_cursor` 不在 request batch sequence 范围内。

## Receiver 算法

正确 receiver 的形状如下：

```text
read headers
verify content-type is application/x-protobuf
decode body using x-traffic-probe-codec
decode BatchEnvelope protobuf
deduplicate by batch_id or idempotency-key
durably store every EventRecord in sequence order
return accepted=true with the last contiguous durable sequence
```

record 尚未 durable 时，receiver 不应返回 `accepted = true`。exporter 的设计语义是
at-least-once，所以 receiver 重启、超时或网络失败后收到重复 batch 是正常情况。

## Exporter 配置示例

```toml
[[exporters]]
id = "primary-webhook"
transport = "webhook"
endpoint = "https://collector.example/probe/batches"
codec = "zstd"
headers = { x_probe_node = "probe-local" }

[exporters.tls]
trust_anchor_refs = ["collector-ca"]
client_certificate_refs = ["collector-client-cert"]
client_private_key_ref = "collector-client-key"
```

TLS refs 指向 `[[tls.materials]]` 条目。配置 exporter TLS material 时，endpoint 必须使用 HTTPS。
