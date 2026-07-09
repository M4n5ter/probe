use std::io::{self, Write};

use serde::Serialize;

use crate::error::AgentError;

pub(super) fn write_stdout(bytes: &[u8]) -> Result<(), AgentError> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    write_output(&mut stdout, bytes)
}

pub(super) fn write_stdout_line(line: impl AsRef<str>) -> Result<(), AgentError> {
    let mut output = Vec::from(line.as_ref().as_bytes());
    output.push(b'\n');
    write_stdout(&output)
}

pub(super) fn write_pretty_json_stdout(value: &impl Serialize) -> Result<(), AgentError> {
    let mut output = serde_json::to_vec_pretty(value)?;
    output.push(b'\n');
    write_stdout(&output)
}

fn write_output(writer: &mut impl Write, bytes: &[u8]) -> Result<(), AgentError> {
    match writer.write_all(bytes).and_then(|()| writer.flush()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(AgentError::Stdout(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn output_writer_treats_broken_pipe_as_clean_shutdown() {
        let mut writer = FailingWriter::new(io::ErrorKind::BrokenPipe);

        write_output(&mut writer, b"{\"kind\":\"status\"}\n")
            .expect("broken pipe should mean the downstream reader closed");
    }

    #[test]
    fn output_writer_reports_other_stdout_errors() {
        let mut writer = FailingWriter::new(io::ErrorKind::PermissionDenied);

        let error = write_output(&mut writer, b"{\"kind\":\"status\"}\n")
            .expect_err("non-broken-pipe stdout errors should still fail");

        assert!(matches!(
            error,
            AgentError::Stdout(source) if source.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn output_writer_flushes_successful_output() {
        let mut writer = Vec::new();

        write_output(&mut writer, b"{\"kind\":\"status\"}\n")
            .expect("successful stdout write should pass");

        assert_eq!(writer, b"{\"kind\":\"status\"}\n");
    }

    struct FailingWriter {
        kind: io::ErrorKind,
    }

    impl FailingWriter {
        fn new(kind: io::ErrorKind) -> Self {
            Self { kind }
        }
    }

    impl io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.kind))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
