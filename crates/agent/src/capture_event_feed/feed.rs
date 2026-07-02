use std::{
    fs::File,
    io::{BufRead, BufReader, Seek},
    path::Path,
};

use crate::json_lines::{JsonLinesEof, JsonLinesRead, JsonLinesReader};
use capture::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider};
use probe_core::{CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource};
use thiserror::Error;

const MAX_CAPTURE_EVENT_FEED_LINE_BYTES: usize = 16 * 1024 * 1024;
const PROVIDER_NAME: &str = "capture_event_feed_jsonl";

#[derive(Debug, Error)]
pub(crate) enum CaptureEventFeedLoadError {
    #[error("failed to open capture event feed {path}: {source}")]
    OpenFile {
        path: String,
        source: std::io::Error,
    },
}

pub(crate) fn load_capture_event_feed_provider(
    path: &Path,
    follow: bool,
) -> Result<JsonLinesCaptureEventFeedProvider<BufReader<File>>, CaptureEventFeedLoadError> {
    load_capture_event_feed_provider_with_contract(
        path,
        follow,
        CaptureEventFeedOriginContract::Any,
    )
}

pub(crate) fn load_l7_mitm_capture_event_feed_provider(
    path: &Path,
    follow: bool,
) -> Result<JsonLinesCaptureEventFeedProvider<BufReader<File>>, CaptureEventFeedLoadError> {
    load_capture_event_feed_provider_with_contract(
        path,
        follow,
        CaptureEventFeedOriginContract::RequiredSource(CaptureSource::L7MitmPlaintext),
    )
}

fn load_capture_event_feed_provider_with_contract(
    path: &Path,
    follow: bool,
    origin_contract: CaptureEventFeedOriginContract,
) -> Result<JsonLinesCaptureEventFeedProvider<BufReader<File>>, CaptureEventFeedLoadError> {
    let file = File::open(path).map_err(|source| CaptureEventFeedLoadError::OpenFile {
        path: path.display().to_string(),
        source,
    })?;
    Ok(JsonLinesCaptureEventFeedProvider::with_origin_contract(
        BufReader::new(file),
        path.display().to_string(),
        follow,
        origin_contract,
    ))
}

#[derive(Debug)]
pub(crate) struct JsonLinesCaptureEventFeedProvider<R> {
    reader: JsonLinesReader<R>,
    follow: bool,
    origin_contract: CaptureEventFeedOriginContract,
}

impl<R> JsonLinesCaptureEventFeedProvider<R>
where
    R: BufRead + Seek,
{
    #[cfg(test)]
    fn new(reader: R, path: impl Into<String>, follow: bool) -> Self {
        Self::with_origin_contract(reader, path, follow, CaptureEventFeedOriginContract::Any)
    }

    #[cfg(test)]
    fn l7_mitm_bridge(reader: R, path: impl Into<String>, follow: bool) -> Self {
        Self::with_origin_contract(
            reader,
            path,
            follow,
            CaptureEventFeedOriginContract::RequiredSource(CaptureSource::L7MitmPlaintext),
        )
    }

    fn with_origin_contract(
        reader: R,
        path: impl Into<String>,
        follow: bool,
        origin_contract: CaptureEventFeedOriginContract,
    ) -> Self {
        Self {
            reader: JsonLinesReader::new(
                reader,
                path,
                "capture event feed",
                MAX_CAPTURE_EVENT_FEED_LINE_BYTES,
            ),
            follow,
            origin_contract,
        }
    }

    fn read_next_poll(&mut self) -> Result<CapturePoll, CaptureEventFeedReadError> {
        let eof = if self.follow {
            JsonLinesEof::Follow
        } else {
            JsonLinesEof::Finish
        };
        match self.reader.read::<CaptureEvent>(eof)? {
            JsonLinesRead::Item(event) => {
                self.origin_contract.validate(&event)?;
                Ok(CapturePoll::event(event))
            }
            JsonLinesRead::Idle => Ok(CapturePoll::Idle),
            JsonLinesRead::Finished => Ok(CapturePoll::Finished),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureEventFeedOriginContract {
    Any,
    RequiredSource(CaptureSource),
}

impl CaptureEventFeedOriginContract {
    fn validate(self, event: &CaptureEvent) -> Result<(), CaptureEventFeedReadError> {
        match self {
            Self::Any => Ok(()),
            Self::RequiredSource(expected) => {
                let actual = capture_event_origin(event).source();
                if actual == expected {
                    Ok(())
                } else {
                    Err(CaptureEventFeedReadError::SourceMismatch { expected, actual })
                }
            }
        }
    }
}

fn capture_event_origin(event: &CaptureEvent) -> CaptureOrigin {
    match event {
        CaptureEvent::Bytes(bytes) => bytes.origin,
        CaptureEvent::Gap(gap) => gap.origin,
        CaptureEvent::Loss(loss) => loss.origin,
        CaptureEvent::ConnectionOpened { origin, .. }
        | CaptureEvent::ConnectionClosed { origin, .. } => *origin,
    }
}

#[derive(Debug, Error)]
enum CaptureEventFeedReadError {
    #[error(transparent)]
    JsonLines(#[from] crate::json_lines::JsonLinesError),
    #[error("capture event feed requires source {expected:?}, got {actual:?}")]
    SourceMismatch {
        expected: CaptureSource,
        actual: CaptureSource,
    },
}

impl<R> CaptureProvider for JsonLinesCaptureEventFeedProvider<R>
where
    R: BufRead + Seek,
{
    fn name(&self) -> &'static str {
        PROVIDER_NAME
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(CapabilityKind::CaptureEventFeed)]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.read_next_poll()
            .map_err(|error| CaptureError::provider(PROVIDER_NAME, error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor};

    use capture::{CaptureProviderKind, CapturedLoss};
    use probe_core::{
        CaptureLoss, CaptureOrigin, CaptureSource, EnforcementEvidence, ObservationOnlyReason,
        Timestamp,
    };

    use super::*;

    #[test]
    fn reads_capture_event_json_lines() -> Result<(), Box<dyn std::error::Error>> {
        let event = capture_loss_event(7);
        let input = json_line(&event)?;
        let mut provider =
            JsonLinesCaptureEventFeedProvider::new(Cursor::new(input), "fixture", false);

        let Some(CaptureEvent::Loss(loss)) = provider.next()? else {
            panic!("expected capture loss");
        };

        assert_eq!(provider.name(), PROVIDER_NAME);
        assert_eq!(
            provider.capabilities(),
            vec![CapabilityState::available(CapabilityKind::CaptureEventFeed)]
        );
        assert_eq!(loss.origin.source(), CaptureSource::EbpfSyscall);
        assert_eq!(loss.origin.provider(), CaptureProviderKind::Ebpf);
        assert_eq!(loss.loss.lost_events, 7);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn follows_feed_at_eof_when_configured() -> Result<(), Box<dyn std::error::Error>> {
        let event = capture_loss_event(3);
        let input = json_line(&event)?;
        let mut provider =
            JsonLinesCaptureEventFeedProvider::new(Cursor::new(input), "fixture", true);

        assert!(matches!(provider.poll_next()?, CapturePoll::Event(_)));
        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));
        Ok(())
    }

    #[test]
    fn follow_mode_waits_for_complete_json_lines() -> Result<(), Box<dyn std::error::Error>> {
        let event = capture_loss_event(5);
        let input = json_line(&event)?;
        let split_at = input.len() / 2;
        let mut provider =
            JsonLinesCaptureEventFeedProvider::new(Cursor::new(Vec::new()), "fixture", true);

        provider
            .reader
            .input_mut()
            .get_mut()
            .extend_from_slice(&input.as_bytes()[..split_at]);
        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));

        provider
            .reader
            .input_mut()
            .get_mut()
            .extend_from_slice(&input.as_bytes()[split_at..]);
        let CapturePoll::Event(event) = provider.poll_next()? else {
            panic!("expected completed capture loss event");
        };
        let CaptureEvent::Loss(loss) = *event else {
            panic!("expected completed capture loss event");
        };

        assert_eq!(loss.loss.lost_events, 5);
        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));
        Ok(())
    }

    #[test]
    fn follow_mode_rewinds_when_feed_file_is_truncated() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::NamedTempFile::new()?;
        let path = temp.path().to_path_buf();
        fs::write(
            &path,
            format!(
                "{}{}",
                json_line(&capture_loss_event(100))?,
                json_line(&capture_loss_event(200))?
            ),
        )?;
        let mut provider = load_capture_event_feed_provider(&path, true)?;

        assert_loss(provider.poll_next()?, 100);
        assert_loss(provider.poll_next()?, 200);
        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));

        fs::write(&path, json_line(&capture_loss_event(3))?)?;

        assert_loss(provider.poll_next()?, 3);
        Ok(())
    }

    #[test]
    fn follow_mode_drops_buffered_partial_line_after_feed_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::NamedTempFile::new()?;
        let path = temp.path().to_path_buf();
        fs::write(&path, "partial")?;
        let mut provider = load_capture_event_feed_provider(&path, true)?;

        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));

        fs::write(&path, json_line(&capture_loss_event(3))?)?;

        assert_loss(provider.poll_next()?, 3);
        Ok(())
    }

    #[test]
    fn follow_mode_rewinds_after_clean_eof_feed_restart() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::NamedTempFile::new()?;
        let path = temp.path().to_path_buf();
        let old_generation = json_line(&capture_loss_event(100))?;
        let new_generation = [
            json_line(&capture_loss_event(3))?,
            json_line(&capture_loss_event(4))?,
            json_line(&capture_loss_event(5))?,
        ]
        .join("");
        assert!(new_generation.len() > old_generation.len());
        fs::write(&path, old_generation)?;
        let mut provider = load_capture_event_feed_provider(&path, true)?;

        assert_loss(provider.poll_next()?, 100);
        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));

        fs::write(&path, new_generation)?;

        assert_loss(provider.poll_next()?, 3);
        Ok(())
    }

    #[test]
    fn rejects_unknown_capture_event_fields() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = serde_json::to_value(capture_loss_event(1))?;
        value["unexpected"] = serde_json::json!(true);
        let input = format!("{value}\n");
        let mut provider =
            JsonLinesCaptureEventFeedProvider::new(Cursor::new(input), "fixture", false);

        let error = provider
            .next()
            .expect_err("unknown JSON fields must fail closed");

        assert!(error.to_string().contains("unknown field"));
        Ok(())
    }

    #[test]
    fn l7_mitm_bridge_feed_rejects_non_mitm_sources() -> Result<(), Box<dyn std::error::Error>> {
        let event = capture_loss_event_with_source(1, CaptureSource::ExternalPlaintextFeed);
        let input = json_line(&event)?;
        let mut provider =
            JsonLinesCaptureEventFeedProvider::l7_mitm_bridge(Cursor::new(input), "fixture", false);

        let error = provider
            .next()
            .expect_err("MITM bridge feed must fail closed on mismatched source");

        assert!(
            error
                .to_string()
                .contains("requires source L7MitmPlaintext"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn rejects_lines_over_the_size_limit() {
        let input = "x".repeat(MAX_CAPTURE_EVENT_FEED_LINE_BYTES + 1);
        let mut provider =
            JsonLinesCaptureEventFeedProvider::new(Cursor::new(input), "fixture", false);

        let error = provider
            .next()
            .expect_err("oversized JSON lines must fail closed");

        assert!(error.to_string().contains("exceeds"));
    }

    fn capture_loss_event(lost_events: u64) -> CaptureEvent {
        capture_loss_event_with_source(lost_events, CaptureSource::EbpfSyscall)
    }

    fn capture_loss_event_with_source(lost_events: u64, source: CaptureSource) -> CaptureEvent {
        let reason = "deterministic provider loss fixture".to_string();
        CaptureEvent::Loss(CapturedLoss {
            timestamp: Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 2,
            },
            origin: CaptureOrigin::from_source(source),
            enforcement_evidence: EnforcementEvidence::observation_only_with_detail(
                ObservationOnlyReason::ProviderCaptureLoss,
                reason.clone(),
            ),
            loss: CaptureLoss {
                lost_events,
                reason,
            },
        })
    }

    fn json_line(event: &CaptureEvent) -> Result<String, serde_json::Error> {
        serde_json::to_string(event).map(|line| format!("{line}\n"))
    }

    fn assert_loss(poll: CapturePoll, lost_events: u64) {
        let CapturePoll::Event(event) = poll else {
            panic!("expected capture event");
        };
        let CaptureEvent::Loss(loss) = *event else {
            panic!("expected loss event");
        };
        assert_eq!(loss.loss.lost_events, lost_events);
    }
}
