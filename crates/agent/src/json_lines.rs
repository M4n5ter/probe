use std::io::{self, BufRead, Seek, SeekFrom};

use serde::de::DeserializeOwned;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonLinesEof {
    Finish,
    Follow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JsonLinesRead<T> {
    Item(T),
    Idle,
    Finished,
}

#[derive(Debug)]
pub(crate) struct JsonLinesReader<R> {
    reader: R,
    source_name: String,
    label: &'static str,
    max_line_bytes: usize,
    line_number: usize,
    line_buffer: Vec<u8>,
    line_start_offset: u64,
    last_complete_line: Option<RecordedLine>,
    poisoned: bool,
}

#[derive(Debug)]
struct RecordedLine {
    start_offset: u64,
    bytes: Vec<u8>,
}

impl<R> JsonLinesReader<R>
where
    R: BufRead + Seek,
{
    pub(crate) fn new(
        reader: R,
        source_name: impl Into<String>,
        label: &'static str,
        max_line_bytes: usize,
    ) -> Self {
        Self {
            reader,
            source_name: source_name.into(),
            label,
            max_line_bytes,
            line_number: 0,
            line_buffer: Vec::new(),
            line_start_offset: 0,
            last_complete_line: None,
            poisoned: false,
        }
    }

    pub(crate) fn read<T>(&mut self, eof: JsonLinesEof) -> Result<JsonLinesRead<T>, JsonLinesError>
    where
        T: DeserializeOwned,
    {
        loop {
            if self.poisoned {
                return Err(JsonLinesError::Poisoned {
                    label: self.label,
                    source_name: self.source_name.clone(),
                    line: self.line_number.saturating_add(1),
                });
            }
            if eof == JsonLinesEof::Follow {
                if self.rewind_if_buffered_line_changed()? {
                    continue;
                }
                if self.line_buffer.is_empty() {
                    self.line_start_offset = self
                        .reader
                        .stream_position()
                        .map_err(|source| self.seek_error(source))?;
                }
            }
            let line = match read_bounded_line(
                &mut self.reader,
                &mut self.line_buffer,
                self.max_line_bytes,
                self.label,
            ) {
                Ok(line) => line,
                Err(source) => {
                    self.line_buffer.clear();
                    self.poisoned = true;
                    return Err(JsonLinesError::ReadLine {
                        label: self.label,
                        source_name: self.source_name.clone(),
                        line: self.line_number.saturating_add(1),
                        source,
                    });
                }
            };
            if line.bytes_read == 0 {
                if eof == JsonLinesEof::Follow && self.rewind_if_past_end()? {
                    continue;
                }
                return Ok(match eof {
                    JsonLinesEof::Finish => JsonLinesRead::Finished,
                    JsonLinesEof::Follow => JsonLinesRead::Idle,
                });
            }
            if eof == JsonLinesEof::Follow && !line.line_ended {
                return Ok(JsonLinesRead::Idle);
            }
            self.line_number = self.line_number.saturating_add(1);
            if eof == JsonLinesEof::Follow {
                self.record_complete_line();
            }
            if self.line_buffer.iter().all(u8::is_ascii_whitespace) {
                self.line_buffer.clear();
                continue;
            }
            let item = match serde_json::from_slice::<T>(&self.line_buffer) {
                Ok(item) => item,
                Err(source) => {
                    self.line_buffer.clear();
                    return Err(JsonLinesError::InvalidJsonLine {
                        label: self.label,
                        source_name: self.source_name.clone(),
                        line: self.line_number,
                        source,
                    });
                }
            };
            self.line_buffer.clear();
            return Ok(JsonLinesRead::Item(item));
        }
    }

    #[cfg(test)]
    pub(crate) fn input_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    fn rewind_if_past_end(&mut self) -> Result<bool, JsonLinesError> {
        let current = self
            .reader
            .stream_position()
            .map_err(|source| self.seek_error(source))?;
        let end = self
            .reader
            .seek(SeekFrom::End(0))
            .map_err(|source| self.seek_error(source))?;
        if current > end {
            self.reader
                .seek(SeekFrom::Start(0))
                .map_err(|source| self.seek_error(source))?;
            self.line_number = 0;
            self.line_buffer.clear();
            self.line_start_offset = 0;
            self.last_complete_line = None;
            return Ok(true);
        }
        self.reader
            .seek(SeekFrom::Start(current))
            .map_err(|source| self.seek_error(source))?;
        Ok(false)
    }

    fn rewind_if_buffered_line_changed(&mut self) -> Result<bool, JsonLinesError> {
        if self.line_buffer.is_empty() {
            return self.rewind_if_last_complete_line_changed();
        }
        let current = self
            .reader
            .stream_position()
            .map_err(|source| self.seek_error(source))?;
        if current
            > self
                .reader
                .seek(SeekFrom::End(0))
                .map_err(|source| self.seek_error(source))?
            || current.saturating_sub(self.line_start_offset)
                != u64::try_from(self.line_buffer.len()).unwrap_or(u64::MAX)
        {
            return self.rewind_after_buffered_line_change();
        }

        self.reader
            .seek(SeekFrom::Start(self.line_start_offset))
            .map_err(|source| self.seek_error(source))?;
        let mut observed = vec![0; self.line_buffer.len()];
        let read_result = self.reader.read_exact(&mut observed);
        self.reader
            .seek(SeekFrom::Start(current))
            .map_err(|source| self.seek_error(source))?;
        match read_result {
            Ok(()) if observed == self.line_buffer => Ok(false),
            Ok(()) => self.rewind_after_buffered_line_change(),
            Err(source) if source.kind() == io::ErrorKind::UnexpectedEof => {
                self.rewind_after_buffered_line_change()
            }
            Err(source) => Err(self.seek_error(source)),
        }
    }

    fn rewind_after_buffered_line_change(&mut self) -> Result<bool, JsonLinesError> {
        self.reader
            .seek(SeekFrom::Start(0))
            .map_err(|source| self.seek_error(source))?;
        self.line_number = 0;
        self.line_buffer.clear();
        self.line_start_offset = 0;
        self.last_complete_line = None;
        Ok(true)
    }

    fn rewind_if_last_complete_line_changed(&mut self) -> Result<bool, JsonLinesError> {
        let Some(recorded) = &self.last_complete_line else {
            return Ok(false);
        };
        let start_offset = recorded.start_offset;
        let expected = recorded.bytes.clone();
        let current = self
            .reader
            .stream_position()
            .map_err(|source| self.seek_error(source))?;
        let changed = self.recorded_bytes_changed(start_offset, &expected, current)?;
        if changed {
            return self.rewind_after_buffered_line_change();
        }
        Ok(false)
    }

    fn recorded_bytes_changed(
        &mut self,
        start_offset: u64,
        expected: &[u8],
        restore_offset: u64,
    ) -> Result<bool, JsonLinesError> {
        self.reader
            .seek(SeekFrom::Start(start_offset))
            .map_err(|source| self.seek_error(source))?;
        let mut observed = vec![0; expected.len()];
        let read_result = self.reader.read_exact(&mut observed);
        self.reader
            .seek(SeekFrom::Start(restore_offset))
            .map_err(|source| self.seek_error(source))?;
        match read_result {
            Ok(()) => Ok(observed != expected),
            Err(source) if source.kind() == io::ErrorKind::UnexpectedEof => Ok(true),
            Err(source) => Err(self.seek_error(source)),
        }
    }

    fn record_complete_line(&mut self) {
        self.last_complete_line = Some(RecordedLine {
            start_offset: self.line_start_offset,
            bytes: self.line_buffer.clone(),
        });
    }

    fn seek_error(&self, source: io::Error) -> JsonLinesError {
        JsonLinesError::ReadLine {
            label: self.label,
            source_name: self.source_name.clone(),
            line: self.line_number.saturating_add(1),
            source,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum JsonLinesError {
    #[error("failed to read {label} {source_name}:{line}: {source}")]
    ReadLine {
        label: &'static str,
        source_name: String,
        line: usize,
        source: io::Error,
    },
    #[error("invalid {label} {source_name}:{line}: {source}")]
    InvalidJsonLine {
        label: &'static str,
        source_name: String,
        line: usize,
        source: serde_json::Error,
    },
    #[error("{label} {source_name}:{line} cannot continue after a previous read error")]
    Poisoned {
        label: &'static str,
        source_name: String,
        line: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BoundedLineRead {
    bytes_read: usize,
    line_ended: bool,
}

fn read_bounded_line<R>(
    reader: &mut R,
    output: &mut Vec<u8>,
    max_bytes: usize,
    label: &str,
) -> io::Result<BoundedLineRead>
where
    R: BufRead,
{
    let mut bytes_read = 0;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if output.len().saturating_add(take) > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} line exceeds {max_bytes} bytes"),
            ));
        }
        let line_ended = available[..take].ends_with(b"\n");
        output.extend_from_slice(&available[..take]);
        reader.consume(take);
        bytes_read += take;
        if line_ended {
            return Ok(BoundedLineRead {
                bytes_read,
                line_ended: true,
            });
        }
    }

    Ok(BoundedLineRead {
        bytes_read,
        line_ended: false,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, PartialEq, Eq, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JsonLineFixture {
        value: u8,
    }

    #[test]
    fn parse_error_does_not_poison_next_line() -> Result<(), Box<dyn std::error::Error>> {
        let input = br#"{"unexpected":true}
{"value":7}
"#;
        let mut reader = JsonLinesReader::new(Cursor::new(input), "fixture", "fixture feed", 1024);

        let error = reader
            .read::<JsonLineFixture>(JsonLinesEof::Finish)
            .expect_err("unknown fields should fail closed");
        assert!(error.to_string().contains("unknown field"));

        assert_eq!(
            reader.read::<JsonLineFixture>(JsonLinesEof::Finish)?,
            JsonLinesRead::Item(JsonLineFixture { value: 7 })
        );
        Ok(())
    }

    #[test]
    fn read_error_poisons_reader() {
        let input = br#"{"value":7}
"#;
        let mut reader = JsonLinesReader::new(Cursor::new(input), "fixture", "fixture feed", 4);

        let first_error = reader
            .read::<JsonLineFixture>(JsonLinesEof::Finish)
            .expect_err("oversized line should fail closed");
        assert!(first_error.to_string().contains("exceeds"));

        let second_error = reader
            .read::<JsonLineFixture>(JsonLinesEof::Finish)
            .expect_err("reader should stay poisoned after read errors");
        assert!(second_error.to_string().contains("previous read error"));
    }
}
