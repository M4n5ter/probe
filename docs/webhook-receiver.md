# Webhook Receiver Reference

Probe webhook exporters deliver durable export batches to an HTTP endpoint. The
transport is at-least-once: receivers must treat `batch_id` or
`idempotency-key` as the idempotency key and commit by cursor only after durable
ingestion.

## Endpoint Rules

Webhook exporters use `exporters.<id>.endpoint`. It must be an absolute
`http://` or `https://` URL with a host, and URL credentials are rejected. TLS
material refs require `https://`.

Other HTTP endpoint fields have different security rules. The endpoint matrix is
documented in [http-endpoints.md](http-endpoints.md).

Custom exporter headers are allowed for deployment metadata, but these protocol
headers are reserved and cannot be overridden:

- `content-type`
- `idempotency-key`
- `x-traffic-probe-codec`

## Request

Probe sends one HTTP request per export batch:

| Part | Value |
| --- | --- |
| Method | `POST` |
| Target | Configured endpoint path and query |
| `content-type` | `application/x-protobuf` |
| `x-traffic-probe-codec` | `none`, `zstd`, `gzip`, or `deflate` |
| `idempotency-key` | The batch id |
| Body | A `BatchEnvelope` protobuf message, compressed according to the codec header |

The manually maintained wire schema is published in
[export-batch.proto](export-batch.proto). The current Rust implementation lives
in `crates/proto/src/batch.rs`; `published_export_batch_proto_matches_wire_contract`
checks the published schema text and a representative protobuf byte encoding
against the hand-written `prost::Message` model.

Each `EventRecord.payload` is a JSON `EventEnvelope` when
`payload_format = PAYLOAD_FORMAT_JSON`. The payload schema string is
`traffic.probe.event_envelope.subject_origin.json`.

## Compression

Decode the request body using the `x-traffic-probe-codec` header:

| Codec | Meaning |
| --- | --- |
| `none` | Body is the raw protobuf bytes. |
| `zstd` | Body is Zstandard-compressed protobuf bytes. |
| `gzip` | Body is gzip-compressed protobuf bytes. |
| `deflate` | Body is zlib/deflate-compressed protobuf bytes. |

Receivers should reject unknown codec values and avoid guessing. The
`BatchEnvelope.codec` field mirrors the configured exporter codec; the header is
the transport contract.

## Acknowledgement

The response body must be UTF-8 JSON and no larger than 64 KiB:

```json
{
  "batch_id": "probe-local:primary-webhook:1-4",
  "accepted": true,
  "acked_cursor": 4,
  "reason": null
}
```

- `batch_id`:
  required. It must match the request batch id.
- `accepted`:
  required. Return `true` only after the receiver durably accepts the
  acknowledged prefix.
- `acked_cursor`:
  required when `accepted = true`. It is the export sequence cursor committed by
  the receiver and must be within the request batch sequence range.
- `reason`:
  optional human-readable rejection or diagnostic reason.

Unknown JSON fields are ignored, so a receiver may attach local metadata.

For a fully consumed batch, set `acked_cursor` to the largest `sequence` in the
batch. For a partial durable commit, set it to the last contiguous committed
sequence. Probe advances the sink cursor to that value and retries later
records according to the export worker schedule.

The sink remains unacked and will be retried when any of these conditions occur:

- non-2xx HTTP status;
- response body is larger than 64 KiB;
- response body is not valid JSON;
- `batch_id` mismatch;
- `accepted = false`;
- accepted response without `acked_cursor`;
- `acked_cursor` outside the request batch sequence range.

## Receiver Algorithm

A correct receiver follows this shape:

```text
read headers
verify content-type is application/x-protobuf
decode body using x-traffic-probe-codec
decode BatchEnvelope protobuf
deduplicate by batch_id or idempotency-key
durably store every EventRecord in sequence order
return accepted=true with the last contiguous durable sequence
```

A receiver should not return `accepted = true` before records are durable. The
exporter is designed around at-least-once delivery, so duplicate batches are
normal after receiver restarts, timeout, or network failure.

## Example Exporter Config

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

TLS refs point to `[[tls.materials]]` entries. When exporter TLS material is
configured, the endpoint must be HTTPS.
