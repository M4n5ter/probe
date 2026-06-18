pub(crate) fn request(request_index: usize, body_bytes: usize) -> Vec<u8> {
    let body = deterministic_body("request", request_index, body_bytes);
    let header = format!(
        "POST /sssa-e2e/{request_index} HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         User-Agent: sssa-e2e-dynssl-fixture\r\n\
         Connection: close\r\n\
         X-SSSA-E2E-Request: {request_index}\r\n\
         Content-Length: {}\r\n\
         \r\n",
        body.len()
    );
    [header.as_bytes(), &body].concat()
}

fn deterministic_body(label: &str, request_index: usize, len: usize) -> Vec<u8> {
    let pattern = format!("sssa-e2e-{label}-{request_index}-");
    let pattern = pattern.as_bytes();
    let mut body = Vec::with_capacity(len);
    while body.len() < len {
        let remaining = len - body.len();
        let take = remaining.min(pattern.len());
        body.extend_from_slice(&pattern[..take]);
    }
    body
}
