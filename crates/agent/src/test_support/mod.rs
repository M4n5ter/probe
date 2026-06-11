use std::{
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const SERVER_IO_TIMEOUT: Duration = Duration::from_secs(2);

pub struct SingleResponseHttpServer {
    endpoint: String,
    handle: thread::JoinHandle<Result<(), String>>,
}

impl SingleResponseHttpServer {
    pub fn spawn(
        path: &str,
        status: &'static str,
        body: impl Into<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = format!("http://{}{}", listener.local_addr()?, path);
        let expected_path = path.to_string();
        let body = body.into();
        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            ready_tx.send(()).map_err(|error| error.to_string())?;
            let mut stream = accept_one(&listener)?;
            stream
                .set_read_timeout(Some(SERVER_IO_TIMEOUT))
                .map_err(|error| error.to_string())?;
            let request = read_headers(&mut stream)?;
            verify_request_path(&request, &expected_path)?;
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .map_err(|error| error.to_string())
        });
        ready_rx.recv_timeout(Duration::from_secs(1))?;
        Ok(Self { endpoint, handle })
    }

    pub fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    pub fn join(self) -> Result<(), Box<dyn std::error::Error>> {
        self.handle
            .join()
            .map_err(|_| "single response HTTP server panicked")?
            .map_err(Into::into)
    }
}

fn accept_one(listener: &TcpListener) -> Result<std::net::TcpStream, String> {
    let deadline = Instant::now() + SERVER_IO_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for HTTP request".to_string());
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn read_headers(stream: &mut std::net::TcpStream) -> Result<String, String> {
    let mut request = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let read = stream.read(&mut buffer).map_err(|error| {
            if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
                "timed out reading HTTP request headers".to_string()
            } else {
                error.to_string()
            }
        })?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(request).map_err(|error| error.to_string())
}

fn verify_request_path(request: &str, expected_path: &str) -> Result<(), String> {
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| "HTTP request has no request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let _method = parts
        .next()
        .ok_or_else(|| "HTTP request line has no method".to_string())?;
    let actual_path = parts
        .next()
        .ok_or_else(|| "HTTP request line has no path".to_string())?;
    if actual_path == expected_path {
        Ok(())
    } else {
        Err(format!(
            "HTTP request path mismatch: expected {expected_path}, got {actual_path}"
        ))
    }
}
