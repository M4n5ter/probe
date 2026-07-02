use std::{
    io::Read,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const OUTPUT_READ_SIZE: usize = 1024;
const OUTPUT_WAIT_TIMEOUT: Duration = Duration::from_millis(100);
const OUTPUT_JOIN_TIMEOUT: Duration = Duration::from_millis(500);

pub(super) struct ManagedProcessOutput {
    handle: ManagedProcessOutputHandle,
    readers: Vec<JoinHandle<()>>,
}

impl ManagedProcessOutput {
    pub(super) fn drain<R, E>(stdout: Option<R>, stderr: Option<E>) -> Self
    where
        R: Read + Send + 'static,
        E: Read + Send + 'static,
    {
        let handle = ManagedProcessOutputHandle::default();
        let mut readers = Vec::new();
        if let Some(stdout) = stdout {
            readers.push(spawn_output_reader(stdout, Arc::clone(&handle.stdout)));
        }
        if let Some(stderr) = stderr {
            readers.push(spawn_output_reader(stderr, Arc::clone(&handle.stderr)));
        }
        Self { handle, readers }
    }

    pub(super) fn handle(&self) -> ManagedProcessOutputHandle {
        self.handle.clone()
    }

    pub(super) fn join_finished(&mut self) {
        let deadline = Instant::now() + OUTPUT_JOIN_TIMEOUT;
        while self.readers.iter().any(|reader| !reader.is_finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let mut pending = Vec::new();
        for reader in self.readers.drain(..) {
            if reader.is_finished() {
                let _ = reader.join();
            } else {
                pending.push(reader);
            }
        }
        self.readers = pending;
    }
}

#[derive(Clone, Default)]
pub(super) struct ManagedProcessOutputHandle {
    stdout: Arc<Mutex<OutputStreamSummary>>,
    stderr: Arc<Mutex<OutputStreamSummary>>,
}

impl ManagedProcessOutputHandle {
    pub(super) fn exit_context(&self) -> Option<String> {
        let deadline = Instant::now() + OUTPUT_WAIT_TIMEOUT;
        while self.summary().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        self.summary()
    }

    fn summary(&self) -> Option<String> {
        let summary = [
            self.stream_summary("stderr", &self.stderr),
            self.stream_summary("stdout", &self.stdout),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
        (!summary.is_empty()).then_some(summary)
    }

    fn stream_summary(
        &self,
        label: &str,
        stream: &Arc<Mutex<OutputStreamSummary>>,
    ) -> Option<String> {
        let stream = stream.lock().ok()?;
        stream.summary(label)
    }
}

#[derive(Default)]
struct OutputStreamSummary {
    bytes: usize,
    read_failed: Option<String>,
}

impl OutputStreamSummary {
    fn record_bytes(&mut self, count: usize) {
        self.bytes = self.bytes.saturating_add(count);
    }

    fn record_read_failure(&mut self, error: std::io::Error) {
        self.read_failed = Some(error.to_string());
    }

    fn summary(&self, label: &str) -> Option<String> {
        if let Some(error) = &self.read_failed {
            return Some(format!("{label} read failed: {error}"));
        }
        (self.bytes > 0).then(|| {
            format!(
                "{label} produced {} byte(s); content omitted because managed backend output may contain decrypted traffic or secrets",
                self.bytes
            )
        })
    }
}

fn spawn_output_reader<R>(mut stream: R, output: Arc<Mutex<OutputStreamSummary>>) -> JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0; OUTPUT_READ_SIZE];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let Ok(mut output) = output.lock() else {
                        break;
                    };
                    output.record_bytes(read);
                }
                Err(error) => {
                    if let Ok(mut output) = output.lock() {
                        output.record_read_failure(error);
                    }
                    break;
                }
            }
        }
    })
}
