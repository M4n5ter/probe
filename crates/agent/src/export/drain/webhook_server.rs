use std::{
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

const WEBHOOK_SERVER_IO_TIMEOUT: Duration = Duration::from_secs(2);

pub(in crate::export::drain) struct WebhookAckServer {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop_requested: Arc<AtomicBool>,
    handle: thread::JoinHandle<Result<(), String>>,
}

impl WebhookAckServer {
    pub(in crate::export::drain) fn accepting(
        request_count: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_with_limit(WebhookAckBehavior::Accept, request_count)
    }

    pub(in crate::export::drain) fn rejecting(
        request_count: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_with_limit(WebhookAckBehavior::Reject, request_count)
    }

    pub(in crate::export::drain) fn recording_accepting() -> Result<Self, Box<dyn std::error::Error>>
    {
        Self::spawn_with_limit(WebhookAckBehavior::Accept, usize::MAX)
    }

    pub(in crate::export::drain) fn recording_rejecting() -> Result<Self, Box<dyn std::error::Error>>
    {
        Self::spawn_with_limit(WebhookAckBehavior::Reject, usize::MAX)
    }

    fn spawn_with_limit(
        behavior: WebhookAckBehavior,
        request_count: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = format!("http://{}/batches", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_requested_for_thread = Arc::clone(&stop_requested);
        let handle = thread::spawn(move || {
            while requests_for_thread
                .lock()
                .map_err(|_| "request lock poisoned".to_string())?
                .len()
                < request_count
            {
                if stop_requested_for_thread.load(Ordering::Relaxed) {
                    break;
                }
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                stream
                    .set_read_timeout(Some(WEBHOOK_SERVER_IO_TIMEOUT))
                    .map_err(|error| error.to_string())?;
                stream
                    .set_write_timeout(Some(WEBHOOK_SERVER_IO_TIMEOUT))
                    .map_err(|error| error.to_string())?;
                let request_text = read_request(&mut stream)?;
                let batch_id = request_header(&request_text, "idempotency-key")
                    .unwrap_or_else(|| "missing-batch".to_string());
                let acked_cursor = behavior.accepted().then(|| cursor_from_batch_id(&batch_id));
                let body = serde_json::json!({
                    "batch_id": batch_id,
                    "accepted": behavior.accepted(),
                    "acked_cursor": acked_cursor,
                    "acked_event_ids": [],
                    "retryable_event_ids": [],
                    "reason": behavior.rejection_reason(),
                })
                .to_string();
                let status = behavior.http_status();
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .map_err(|error| error.to_string())?;
                requests_for_thread
                    .lock()
                    .map_err(|_| "request lock poisoned".to_string())?
                    .push(request_text);
            }
            Ok(())
        });
        Ok(Self {
            endpoint,
            requests,
            stop_requested,
            handle,
        })
    }

    pub(in crate::export::drain) fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    pub(in crate::export::drain) fn join(self) -> Result<String, Box<dyn std::error::Error>> {
        let mut requests = self.join_requests()?;
        if requests.len() != 1 {
            return Err(format!(
                "webhook server captured {} requests; expected 1",
                requests.len()
            )
            .into());
        }
        Ok(requests.remove(0))
    }

    pub(in crate::export::drain) fn join_requests(
        self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        self.stop_requested.store(true, Ordering::Relaxed);
        self.handle
            .join()
            .map_err(|_| "webhook server thread panicked")?
            .map_err(|error| format!("webhook server failed: {error}"))?;
        let requests = self
            .requests
            .lock()
            .map_err(|_| "request lock poisoned")?
            .clone();
        if requests.is_empty() {
            Err("webhook server did not capture a request".into())
        } else {
            Ok(requests)
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum WebhookAckBehavior {
    Accept,
    Reject,
}

impl WebhookAckBehavior {
    fn accepted(self) -> bool {
        matches!(self, Self::Accept)
    }

    fn http_status(self) -> &'static str {
        match self {
            Self::Accept => "200 OK",
            Self::Reject => "500 Internal Server Error",
        }
    }

    fn rejection_reason(self) -> Option<&'static str> {
        match self {
            Self::Accept => None,
            Self::Reject => Some("failed"),
        }
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Result<String, String> {
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
    let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
    let content_length = request_header(&headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body_bytes_read = bytes.len().saturating_sub(header_end);
    while body_bytes_read < content_length {
        let mut buffer = [0; 4096];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("connection closed before HTTP body completed".to_string());
        }
        body_bytes_read += read;
    }
    Ok(headers)
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn cursor_from_batch_id(batch_id: &str) -> u64 {
    batch_id
        .rsplit(':')
        .next()
        .and_then(|sequence| sequence.parse().ok())
        .unwrap_or(0)
}

pub(in crate::export::drain) fn request_header(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}
