use std::fmt;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use evidence::ContentDigest;
use zeroize::Zeroize;

use super::format::{DataFrameHeader, FRAME_HEADER_LEN, SegmentFormatError};

pub struct SegmentKey([u8; 32]);

impl SegmentKey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn nonce(&self, segment_header: ContentDigest, sequence: u64) -> [u8; 24] {
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(b"probe-segment-frame-nonce\0");
        hasher.update(segment_header.as_bytes());
        hasher.update(&sequence.to_be_bytes());
        let mut nonce = [0_u8; 24];
        nonce.copy_from_slice(&hasher.finalize().as_bytes()[..24]);
        nonce
    }

    pub(crate) fn encrypt(
        &self,
        segment_header: ContentDigest,
        frame: DataFrameHeader,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SegmentCryptoError> {
        let cipher = self.cipher()?;
        let nonce = XNonce::from(frame.nonce);
        let frame_bytes = frame.encode().map_err(SegmentCryptoError::Format)?;
        let aad = frame_aad(segment_header, &frame_bytes);
        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SegmentCryptoError::Authentication)
    }

    pub(crate) fn decrypt(
        &self,
        segment_header: ContentDigest,
        frame: DataFrameHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SegmentCryptoError> {
        let cipher = self.cipher()?;
        let nonce = XNonce::from(frame.nonce);
        let frame_bytes = frame.encode().map_err(SegmentCryptoError::Format)?;
        let aad = frame_aad(segment_header, &frame_bytes);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SegmentCryptoError::Authentication)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, SegmentCryptoError> {
        XChaCha20Poly1305::new_from_slice(&self.0).map_err(|_| SegmentCryptoError::InvalidKey)
    }
}

impl Drop for SegmentKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentCryptoError {
    InvalidKey,
    Authentication,
    Format(SegmentFormatError),
}

impl fmt::Display for SegmentCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => formatter.write_str("segment encryption key is invalid"),
            Self::Authentication => formatter.write_str("segment frame authentication failed"),
            Self::Format(error) => write!(formatter, "invalid segment frame: {error}"),
        }
    }
}

impl std::error::Error for SegmentCryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Format(error) => Some(error),
            Self::InvalidKey | Self::Authentication => None,
        }
    }
}

fn frame_aad(
    segment_header: ContentDigest,
    frame_header: &[u8; FRAME_HEADER_LEN],
) -> [u8; 32 + FRAME_HEADER_LEN] {
    let mut aad = [0_u8; 32 + FRAME_HEADER_LEN];
    aad[..32].copy_from_slice(segment_header.as_bytes());
    aad[32..].copy_from_slice(frame_header);
    aad
}

#[cfg(test)]
mod tests {
    use evidence::EvidenceId;

    use super::*;
    use crate::{BatchId, RecordKind};

    #[test]
    fn authenticates_header_and_ciphertext_together() {
        let key = SegmentKey::new([7; 32]);
        let segment = ContentDigest::for_bytes(b"segment");
        let frame = DataFrameHeader {
            sequence: 1,
            batch: BatchId::new(2).expect("batch ID"),
            evidence: EvidenceId::new(3).expect("evidence ID"),
            kind: RecordKind::Packet,
            starts_record: true,
            ends_record: true,
            logical_offset: 0,
            plaintext_len: 7,
            nonce: key.nonce(segment, 1),
            plaintext_digest: ContentDigest::for_bytes(b"payload"),
        };
        let encrypted = key.encrypt(segment, frame, b"payload").expect("encrypt");
        assert_eq!(
            key.decrypt(segment, frame, &encrypted).expect("decrypt"),
            b"payload"
        );

        let mut changed = frame;
        changed.logical_offset = 1;
        assert_eq!(
            key.decrypt(segment, changed, &encrypted),
            Err(SegmentCryptoError::Authentication)
        );
    }
}
