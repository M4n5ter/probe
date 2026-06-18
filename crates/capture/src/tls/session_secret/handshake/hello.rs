use super::{TLS_SUPPORTED_VERSIONS_EXTENSION, TLS13_VERSION};
use crate::tls::session_secret::TlsCipherSuite;
use crate::tls::{TLS_RANDOM_BYTES, TlsRandom};

pub(super) const TLS13_HELLO_RETRY_REQUEST_RANDOM: [u8; TLS_RANDOM_BYTES] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub(super) fn parse_tls13_client_hello(body: &[u8]) -> Option<TlsRandom> {
    let random = tls_random_at(body, 2)?;
    let mut cursor = 2 + TLS_RANDOM_BYTES;
    cursor = skip_u8_len(body, cursor)?;
    let cipher_suites_len = read_u16(body, cursor)? as usize;
    cursor = cursor.checked_add(2 + cipher_suites_len)?;
    cursor = skip_u8_len(body, cursor)?;
    let extensions = extensions(body, cursor)?;
    client_hello_supports_tls13(extensions).then_some(random)
}

pub(super) fn parse_tls13_server_hello(body: &[u8]) -> Option<ParsedServerHello> {
    let server_random = tls_random_at(body, 2)?;
    if server_random.as_bytes() == &TLS13_HELLO_RETRY_REQUEST_RANDOM {
        return None;
    }
    let mut cursor = 2 + TLS_RANDOM_BYTES;
    cursor = skip_u8_len(body, cursor)?;
    let cipher_suite = TlsCipherSuite::from_code(read_u16(body, cursor)?);
    cursor = cursor.checked_add(3)?;
    let extensions = extensions(body, cursor)?;
    server_hello_selects_tls13(extensions).then_some(ParsedServerHello {
        server_random,
        cipher_suite,
    })
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ParsedServerHello {
    pub(super) server_random: TlsRandom,
    pub(super) cipher_suite: TlsCipherSuite,
}

fn tls_random_at(body: &[u8], offset: usize) -> Option<TlsRandom> {
    Some(TlsRandom::from_bytes(
        body.get(offset..offset + TLS_RANDOM_BYTES)?
            .try_into()
            .ok()?,
    ))
}

fn extensions(body: &[u8], cursor: usize) -> Option<&[u8]> {
    let extensions_len = read_u16(body, cursor)? as usize;
    let start = cursor.checked_add(2)?;
    let end = start.checked_add(extensions_len)?;
    (end == body.len()).then(|| body.get(start..end)).flatten()
}

fn client_hello_supports_tls13(mut extensions: &[u8]) -> bool {
    let mut supports_tls13 = None;
    while !extensions.is_empty() {
        let Some((extension_type, extension, remaining)) = next_extension(extensions) else {
            return false;
        };
        if extension_type != TLS_SUPPORTED_VERSIONS_EXTENSION {
            extensions = remaining;
            continue;
        }
        if supports_tls13
            .replace(client_supported_versions_extension_selects_tls13(extension))
            .is_some()
        {
            return false;
        }
        extensions = remaining;
    }
    supports_tls13.unwrap_or(false)
}

fn client_supported_versions_extension_selects_tls13(extension: &[u8]) -> bool {
    let Some(len) = extension.first().map(|len| *len as usize) else {
        return false;
    };
    if extension.len() != 1 + len || len % 2 != 0 {
        return false;
    }
    extension[1..]
        .chunks_exact(2)
        .any(|version| version == TLS13_VERSION)
}

fn server_hello_selects_tls13(mut extensions: &[u8]) -> bool {
    let mut selects_tls13 = None;
    while !extensions.is_empty() {
        let Some((extension_type, extension, remaining)) = next_extension(extensions) else {
            return false;
        };
        if extension_type != TLS_SUPPORTED_VERSIONS_EXTENSION {
            extensions = remaining;
            continue;
        }
        if selects_tls13.replace(extension == TLS13_VERSION).is_some() {
            return false;
        }
        extensions = remaining;
    }
    selects_tls13.unwrap_or(false)
}

fn next_extension(extensions: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    let extension_type = read_u16(extensions, 0)?;
    let extension_len = read_u16(extensions, 2)? as usize;
    let end = 4usize.checked_add(extension_len)?;
    Some((
        extension_type,
        extensions.get(4..end)?,
        extensions.get(end..)?,
    ))
}

fn skip_u8_len(body: &[u8], cursor: usize) -> Option<usize> {
    let len = *body.get(cursor)? as usize;
    cursor
        .checked_add(1 + len)
        .filter(|offset| *offset <= body.len())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_RANDOM: [u8; TLS_RANDOM_BYTES] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const SERVER_RANDOM: [u8; TLS_RANDOM_BYTES] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];

    #[test]
    fn client_hello_rejects_trailing_bytes_after_extensions() {
        let mut body = client_hello_body();
        body.push(0);

        assert!(parse_tls13_client_hello(&body).is_none());
    }

    #[test]
    fn client_hello_rejects_malformed_supported_versions_vector() {
        let mut body = client_hello_body_with_extensions(vec![
            0x00,
            0x2b,
            0x00,
            0x04,
            0x02,
            TLS13_VERSION[0],
            TLS13_VERSION[1],
            0x00,
        ]);

        assert!(parse_tls13_client_hello(&body).is_none());
        body = client_hello_body_with_extensions(vec![
            0x00,
            0x2b,
            0x00,
            0x04,
            0x03,
            TLS13_VERSION[0],
            TLS13_VERSION[1],
            0x00,
        ]);
        assert!(parse_tls13_client_hello(&body).is_none());
    }

    #[test]
    fn client_hello_rejects_malformed_extension_tail_after_supported_versions() {
        let mut extensions = supported_versions_client_extension();
        extensions.push(0);
        let body = client_hello_body_with_extensions(extensions);

        assert!(parse_tls13_client_hello(&body).is_none());
    }

    #[test]
    fn server_hello_rejects_trailing_bytes_after_extensions() {
        let mut body = server_hello_body();
        body.push(0);

        assert!(parse_tls13_server_hello(&body).is_none());
    }

    #[test]
    fn server_hello_rejects_malformed_extension_tail_after_supported_versions() {
        let mut body = server_hello_body();
        let extensions_len_offset = 2 + TLS_RANDOM_BYTES + 1 + 2 + 1;
        let extensions_len = read_u16(&body, extensions_len_offset).expect("server hello body");
        body[extensions_len_offset..extensions_len_offset + 2]
            .copy_from_slice(&(extensions_len + 1).to_be_bytes());
        body.push(0);

        assert!(parse_tls13_server_hello(&body).is_none());
    }

    fn client_hello_body() -> Vec<u8> {
        client_hello_body_with_extensions(supported_versions_client_extension())
    }

    fn client_hello_body_with_extensions(extensions: Vec<u8>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&CLIENT_RANDOM);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        body
    }

    fn server_hello_body() -> Vec<u8> {
        let extension = vec![0x00, 0x2b, 0x00, 0x02, TLS13_VERSION[0], TLS13_VERSION[1]];
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&SERVER_RANDOM);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0);
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension);
        body
    }

    fn supported_versions_client_extension() -> Vec<u8> {
        vec![
            0x00,
            0x2b,
            0x00,
            0x03,
            0x02,
            TLS13_VERSION[0],
            TLS13_VERSION[1],
        ]
    }
}
