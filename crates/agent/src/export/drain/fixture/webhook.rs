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

pub(in crate::export::drain) struct TestWebhookServer {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop_requested: Arc<AtomicBool>,
    handle: thread::JoinHandle<Result<(), String>>,
}

impl TestWebhookServer {
    pub(in crate::export::drain) fn spawn(
        accepted: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_accepting(accepted, 1)
    }

    pub(in crate::export::drain) fn spawn_accepting(
        accepted: bool,
        request_count: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_with_limit(accepted, request_count)
    }

    pub(in crate::export::drain) fn spawn_recording(
        accepted: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_with_limit(accepted, usize::MAX)
    }

    fn spawn_with_limit(
        accepted: bool,
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
                let request_text = read_headers(&mut stream)?;
                let batch_id = request_header(&request_text, "idempotency-key")
                    .unwrap_or_else(|| "missing-batch".to_string());
                let acked_cursor = accepted.then(|| cursor_from_batch_id(&batch_id));
                let body = serde_json::json!({
                    "batch_id": batch_id,
                    "accepted": accepted,
                    "acked_cursor": acked_cursor,
                    "acked_event_ids": [],
                    "retryable_event_ids": [],
                    "reason": if accepted { None::<String> } else { Some("failed".to_string()) },
                })
                .to_string();
                let status = if accepted {
                    "200 OK"
                } else {
                    "500 Internal Server Error"
                };
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

fn read_headers(stream: &mut std::net::TcpStream) -> Result<String, String> {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
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
