use std::io::Read;

use crate::{MitmProxyError, error::io_error};

pub(super) const MAX_HEADER_BYTES: usize = 16 * 1024;
pub(super) const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;

pub(super) fn parse_header(line: &str) -> Result<(String, String), MitmProxyError> {
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| MitmProxyError::Http(format!("invalid HTTP header line {line:?}")))?;
    Ok((name.trim().to_string(), value.trim().to_string()))
}

pub(super) fn optional_content_length(
    headers: &[(String, String)],
) -> Result<Option<usize>, MitmProxyError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str());
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.any(|other| other != value) {
        return Err(MitmProxyError::Http(
            "conflicting Content-Length headers".to_string(),
        ));
    }
    value
        .parse::<usize>()
        .map_err(|error| MitmProxyError::Http(format!("invalid Content-Length: {error}")))
        .map(Some)
}

pub(super) fn transfer_encodings(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|encoding| !encoding.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

pub(super) fn connection_tokens(headers: &[(String, String)]) -> impl Iterator<Item = &str> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

pub(super) fn parse_chunk_size(line: &[u8]) -> Result<usize, MitmProxyError> {
    let line = std::str::from_utf8(line)
        .map_err(|error| MitmProxyError::Http(format!("HTTP chunk size is not UTF-8: {error}")))?;
    let size = line.split_once(';').map_or(line, |(size, _)| size).trim();
    if size.is_empty() {
        return Err(MitmProxyError::Http("empty HTTP chunk size".to_string()));
    }
    usize::from_str_radix(size, 16)
        .map_err(|error| MitmProxyError::Http(format!("invalid HTTP chunk size: {error}")))
}

pub(super) fn find_header_terminator(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

pub(super) fn read_more(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<usize, MitmProxyError> {
    if raw.len() >= max_bytes {
        return Err(MitmProxyError::Http(format!(
            "HTTP message exceeded {max_bytes} bytes"
        )));
    }
    let mut buffer = [0_u8; 1024];
    let capacity = buffer.len().min(max_bytes - raw.len());
    let read = stream
        .read(&mut buffer[..capacity])
        .map_err(io_error("read MITM proxy HTTP message"))?;
    raw.extend_from_slice(&buffer[..read]);
    Ok(read)
}

pub(super) fn error_is_read_timeout(error: &MitmProxyError) -> bool {
    matches!(
        error,
        MitmProxyError::Io { source, .. }
            if matches!(
                source.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
    )
}
