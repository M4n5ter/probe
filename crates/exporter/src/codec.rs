use std::io::{Cursor, Read, Write};

use bytes::Bytes;
use flate2::{
    Compression,
    read::{DeflateDecoder, GzDecoder},
    write::{DeflateEncoder, GzEncoder},
};
use serde::{Deserialize, Serialize};

use crate::ExportError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodec {
    None,
    Zstd,
    Gzip,
    Deflate,
}

impl CompressionCodec {
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
        }
    }

    pub fn encode(self, bytes: &[u8]) -> Result<Bytes, ExportError> {
        match self {
            Self::None => Ok(Bytes::copy_from_slice(bytes)),
            Self::Zstd => zstd::stream::encode_all(Cursor::new(bytes), 0)
                .map(Bytes::from)
                .map_err(ExportError::Zstd),
            Self::Gzip => {
                encode_with_writer(GzEncoder::new(Vec::new(), Compression::default()), bytes)
            }
            Self::Deflate => encode_with_writer(
                DeflateEncoder::new(Vec::new(), Compression::default()),
                bytes,
            ),
        }
    }

    pub fn decode(self, bytes: &[u8]) -> Result<Bytes, ExportError> {
        match self {
            Self::None => Ok(Bytes::copy_from_slice(bytes)),
            Self::Zstd => zstd::stream::decode_all(Cursor::new(bytes))
                .map(Bytes::from)
                .map_err(ExportError::Zstd),
            Self::Gzip => decode_with_reader(GzDecoder::new(Cursor::new(bytes))),
            Self::Deflate => decode_with_reader(DeflateDecoder::new(Cursor::new(bytes))),
        }
    }
}

fn encode_with_writer<W>(mut writer: W, bytes: &[u8]) -> Result<Bytes, ExportError>
where
    W: Write + FinishVec,
{
    writer.write_all(bytes).map_err(ExportError::Compression)?;
    writer
        .finish_vec()
        .map(Bytes::from)
        .map_err(ExportError::Compression)
}

fn decode_with_reader<R>(mut reader: R) -> Result<Bytes, ExportError>
where
    R: Read,
{
    let mut decoded = Vec::new();
    reader
        .read_to_end(&mut decoded)
        .map_err(ExportError::Compression)?;
    Ok(Bytes::from(decoded))
}

trait FinishVec {
    fn finish_vec(self) -> std::io::Result<Vec<u8>>;
}

impl FinishVec for GzEncoder<Vec<u8>> {
    fn finish_vec(self) -> std::io::Result<Vec<u8>> {
        self.finish()
    }
}

impl FinishVec for DeflateEncoder<Vec<u8>> {
    fn finish_vec(self) -> std::io::Result<Vec<u8>> {
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codecs_roundtrip_payload() -> Result<(), Box<dyn std::error::Error>> {
        let payload = b"large enough payload large enough payload large enough payload";
        for codec in [
            CompressionCodec::None,
            CompressionCodec::Zstd,
            CompressionCodec::Gzip,
            CompressionCodec::Deflate,
        ] {
            let encoded = codec.encode(payload)?;
            let decoded = codec.decode(&encoded)?;
            assert_eq!(&decoded[..], payload);
        }
        Ok(())
    }
}
