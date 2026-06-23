use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use exporter::{CompressionCodec, WebhookAck};
use proto::BatchEnvelope;

const REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(3);
const BATCH_POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) struct WebhookBatchReceiver {
    endpoint: String,
    listen_port: u16,
    stop_requested: Arc<AtomicBool>,
    batches: Arc<Mutex<Vec<ReceivedBatch>>>,
    handle: Option<thread::JoinHandle<Result<(), String>>>,
}

impl WebhookBatchReceiver {
    pub(crate) fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let listen_addr = listener.local_addr()?;
        let endpoint = format!("http://{listen_addr}/batches");
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_requested_for_thread = Arc::clone(&stop_requested);
        let batches = Arc::new(Mutex::new(Vec::new()));
        let batches_for_thread = Arc::clone(&batches);
        let handle = thread::spawn(move || {
            while !stop_requested_for_thread.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                stream
                    .set_read_timeout(Some(REQUEST_IO_TIMEOUT))
                    .map_err(|error| error.to_string())?;
                stream
                    .set_write_timeout(Some(REQUEST_IO_TIMEOUT))
                    .map_err(|error| error.to_string())?;
                let request = read_http_request(&mut stream)?;
                let received = decode_received_batch(&request)?;
                let response = accepted_response(&received.batch);
                stream
                    .write_all(response.as_bytes())
                    .map_err(|error| error.to_string())?;
                batches_for_thread
                    .lock()
                    .map_err(|_| "batch lock poisoned".to_string())?
                    .push(received);
            }
            Ok(())
        });

        Ok(Self {
            endpoint,
            listen_port: listen_addr.port(),
            stop_requested,
            batches,
            handle: Some(handle),
        })
    }

    pub(crate) fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    pub(crate) fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub(crate) fn wait_for_batches(
        &self,
        expected: usize,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            let observed = self
                .batches
                .lock()
                .map_err(|_| "batch lock poisoned")?
                .len();
            if observed >= expected {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "webhook receiver observed {observed} batch(es), expected at least {expected}"
                )
                .into());
            }
            thread::sleep(BATCH_POLL_INTERVAL);
        }
    }

    pub(crate) fn join(mut self) -> Result<Vec<ReceivedBatch>, Box<dyn std::error::Error>> {
        self.stop_and_join()
            .map_err(|error| format!("webhook receiver failed: {error}"))?;
        let batches = self
            .batches
            .lock()
            .map_err(|_| "batch lock poisoned")?
            .clone();
        if batches.is_empty() {
            Err("webhook receiver captured no batches".into())
        } else {
            Ok(batches)
        }
    }

    fn stop_and_join(&mut self) -> Result<(), String> {
        self.stop_requested.store(true, Ordering::Relaxed);
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle
            .join()
            .map_err(|_| "webhook receiver thread panicked".to_string())?
    }
}

impl Drop for WebhookBatchReceiver {
    fn drop(&mut self) {
        if let Err(error) = self.stop_and_join() {
            eprintln!("webhook receiver cleanup failed: {error}");
        }
    }
}

#[derive(Clone)]
pub(crate) struct ReceivedBatch {
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) codec: CompressionCodec,
    pub(crate) batch: BatchEnvelope,
}

struct HttpRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut buffer = [0; 1024];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("connection closed before HTTP headers completed".to_string());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = header_end(&bytes) {
            break header_end;
        }
    };
    let headers_text = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
    let (method, target) = parse_request_line(&headers_text)?;
    let headers = parse_headers(&headers_text);
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| "webhook request is missing content-length".to_string())?;
    let expected_len = header_end.saturating_add(content_length);
    while bytes.len() < expected_len {
        let mut buffer = [0; 8192];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("connection closed before HTTP body completed".to_string());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(HttpRequest {
        method,
        target,
        headers,
        body: bytes[header_end..expected_len].to_vec(),
    })
}

fn decode_received_batch(request: &HttpRequest) -> Result<ReceivedBatch, String> {
    if request.method != "POST" || request.target != "/batches" {
        return Err(format!(
            "webhook request used unexpected target {} {}",
            request.method, request.target
        ));
    }
    if required_header(request, "content-type")? != "application/x-protobuf" {
        return Err("webhook request used unexpected content-type".to_string());
    }
    let codec = codec_from_header(request)?;
    let decoded = codec
        .decode(&request.body)
        .map_err(|error| error.to_string())?;
    let batch = BatchEnvelope::decode_from_slice(&decoded).map_err(|error| error.to_string())?;
    if batch.codec != codec.wire_name() {
        return Err(format!(
            "batch codec {} does not match webhook header {}",
            batch.codec,
            codec.wire_name()
        ));
    }
    if batch.batch_id != required_header(request, "idempotency-key")? {
        return Err("batch id does not match idempotency-key header".to_string());
    }
    Ok(ReceivedBatch {
        headers: request.headers.clone(),
        codec,
        batch,
    })
}

fn codec_from_header(request: &HttpRequest) -> Result<CompressionCodec, String> {
    let codec = required_header(request, "x-sssa-codec")?;
    CompressionCodec::from_wire_name(&codec)
        .ok_or_else(|| format!("unsupported webhook codec {codec}"))
}

fn required_header(request: &HttpRequest, name: &str) -> Result<String, String> {
    request
        .headers
        .get(name)
        .cloned()
        .ok_or_else(|| format!("webhook request is missing {name} header"))
}

fn accepted_response(batch: &BatchEnvelope) -> String {
    let acked_cursor = batch
        .events
        .iter()
        .map(|event| event.sequence)
        .max()
        .unwrap_or(0);
    let body = serde_json::to_string(&WebhookAck {
        batch_id: batch.batch_id.clone(),
        accepted: true,
        acked_cursor: Some(acked_cursor),
        reason: None,
    })
    .expect("webhook ack serialization should not fail");
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn parse_request_line(headers: &str) -> Result<(String, String), String> {
    let line = headers
        .lines()
        .next()
        .ok_or_else(|| "webhook request is missing request line".to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "webhook request line is missing method".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "webhook request line is missing target".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "webhook request line is missing version".to_string())?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(format!("invalid webhook request line {line}"));
    }
    Ok((method.to_string(), target.to_string()))
}

fn parse_headers(headers: &str) -> BTreeMap<String, String> {
    headers
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}
