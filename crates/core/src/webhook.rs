pub const WEBHOOK_CONTENT_TYPE_HEADER: &str = "content-type";
pub const WEBHOOK_CONTENT_TYPE_PROTOBUF: &str = "application/x-protobuf";
pub const WEBHOOK_CODEC_HEADER: &str = "x-traffic-probe-codec";
pub const WEBHOOK_IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub const RESERVED_WEBHOOK_HEADERS: &[&str] = &[
    WEBHOOK_CONTENT_TYPE_HEADER,
    WEBHOOK_IDEMPOTENCY_KEY_HEADER,
    WEBHOOK_CODEC_HEADER,
];
