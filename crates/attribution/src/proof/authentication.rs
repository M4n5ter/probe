use std::fmt;

use blake3::Hasher;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityKeyError;

impl fmt::Display for AuthorityKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authority key must not be all zero")
    }
}

impl std::error::Error for AuthorityKeyError {}

pub(super) fn validate_authority_key(key: [u8; 32]) -> Result<[u8; 32], AuthorityKeyError> {
    if key == [0; 32] {
        Err(AuthorityKeyError)
    } else {
        Ok(key)
    }
}

pub(super) fn keyed_authenticator(key: &[u8; 32], domain: &[u8], digest: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(domain);
    hasher.update(digest);
    *hasher.finalize().as_bytes()
}

pub(super) fn authenticators_match(expected: [u8; 32], actual: [u8; 32]) -> bool {
    expected
        .iter()
        .zip(actual)
        .fold(0_u8, |difference, (expected, actual)| {
            difference | (expected ^ actual)
        })
        == 0
}
