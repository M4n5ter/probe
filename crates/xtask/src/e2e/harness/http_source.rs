use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

const REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct HttpSourceServer {
    endpoint: String,
    listen_port: u16,
    request_count: Arc<AtomicUsize>,
    body: Arc<Mutex<String>>,
    stop_requested: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<Result<(), String>>>,
}

impl HttpSourceServer {
    pub(crate) fn spawn(
        target: impl Into<String>,
        content_type: &'static str,
        body: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let target = target.into();
        if !target.starts_with('/') {
            return Err(super::e2e_error(format!(
                "HTTP source target must start with '/', got {target}"
            ))
            .into());
        }

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let listen_port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let endpoint = format!("http://{}{}", listener.local_addr()?, target);
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_thread = Arc::clone(&request_count);
        let body = Arc::new(Mutex::new(body));
        let body_for_thread = Arc::clone(&body);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_requested_for_thread = Arc::clone(&stop_requested);
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
                let (method, request_target) = read_http_request(&mut stream)?;
                if method != "GET" || request_target != target {
                    let response =
                        "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                    stream
                        .write_all(response.as_bytes())
                        .map_err(|error| error.to_string())?;
                    return Err(format!(
                        "unexpected HTTP source request {method} {request_target}"
                    ));
                }
                let body = body_for_thread
                    .lock()
                    .map_err(|_| "HTTP source body lock was poisoned".to_string())?
                    .clone();
                let response = http_response(content_type, &body);
                stream
                    .write_all(response.as_bytes())
                    .map_err(|error| error.to_string())?;
                request_count_for_thread.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        });

        Ok(Self {
            endpoint,
            listen_port,
            request_count,
            body,
            stop_requested,
            handle: Some(handle),
        })
    }

    pub(crate) fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    pub(crate) fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub(crate) fn request_count(&self) -> usize {
        self.request_count.load(Ordering::Relaxed)
    }

    pub(crate) fn replace_body(&self, body: String) -> Result<(), Box<dyn std::error::Error>> {
        *self
            .body
            .lock()
            .map_err(|_| super::e2e_error("HTTP source body lock was poisoned"))? = body;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<usize, Box<dyn std::error::Error>> {
        self.stop_and_join()
            .map_err(|error| super::e2e_error(format!("HTTP source server failed: {error}")))?;
        Ok(self.request_count.load(Ordering::Relaxed))
    }

    fn stop_and_join(&mut self) -> Result<(), String> {
        self.stop_requested.store(true, Ordering::Relaxed);
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle
            .join()
            .map_err(|_| "HTTP source server thread panicked".to_string())?
    }
}

impl Drop for HttpSourceServer {
    fn drop(&mut self) {
        if let Err(error) = self.stop_and_join() {
            eprintln!("HTTP source server cleanup failed: {error}");
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> Result<(String, String), String> {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err(
                "connection closed before HTTP source request headers completed".to_string(),
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
        if header_end(&bytes).is_some() {
            break;
        }
    }
    let headers = String::from_utf8_lossy(&bytes);
    let line = headers
        .lines()
        .next()
        .ok_or_else(|| "HTTP source request is missing request line".to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "HTTP source request line is missing method".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "HTTP source request line is missing target".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "HTTP source request line is missing version".to_string())?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(format!("invalid HTTP source request line {line}"));
    }
    Ok((method.to_string(), target.to_string()))
}

fn http_response(content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}
