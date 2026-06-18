use std::fmt;

pub const TLS_RANDOM_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsRandom([u8; TLS_RANDOM_BYTES]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMaterialLookup<'a, T> {
    Missing,
    Found(&'a T),
    Ambiguous { matches: usize },
}

impl TlsRandom {
    pub fn from_bytes(bytes: [u8; TLS_RANDOM_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(value: &str) -> Option<Self> {
        decode_fixed_hex(value).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; TLS_RANDOM_BYTES] {
        &self.0
    }
}

impl fmt::Debug for TlsRandom {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsRandom(")?;
        write_hex(formatter, &self.0)?;
        formatter.write_str(")")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TlsSecret {
    bytes: Box<[u8]>,
}

impl TlsSecret {
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        (!bytes.is_empty()).then(|| Self {
            bytes: bytes.into_boxed_slice(),
        })
    }

    pub fn from_hex(value: &str) -> Option<Self> {
        Self::from_bytes(decode_hex(value)?)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for TlsSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsSecret")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

pub(in crate::tls) fn hex_len(value: &str) -> Option<usize> {
    is_hex(value).then_some(value.len() / 2)
}

pub(in crate::tls) fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !is_hex(value) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = hex_value(chunk[0])?;
            let low = hex_value(chunk[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

pub(in crate::tls) fn decode_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = decode_hex(value)?;
    bytes.try_into().ok()
}

pub(in crate::tls) fn resolve_lookup<'a, T>(
    mut matches: impl Iterator<Item = &'a T>,
) -> TlsMaterialLookup<'a, T> {
    let Some(first) = matches.next() else {
        return TlsMaterialLookup::Missing;
    };
    if matches.next().is_some() {
        return TlsMaterialLookup::Ambiguous {
            matches: 2 + matches.count(),
        };
    }
    TlsMaterialLookup::Found(first)
}

fn is_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_secret_debug_redacts_bytes() {
        let secret = TlsSecret::from_hex("deadbeef").expect("valid secret");

        assert_eq!(secret.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("len"));
        assert!(!rendered.contains("deadbeef"));
    }
}
