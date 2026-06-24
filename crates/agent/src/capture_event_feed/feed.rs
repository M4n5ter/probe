use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use crate::json_lines::{JsonLinesEof, JsonLinesRead, JsonLinesReader};
use capture::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider};
use probe_core::{CapabilityKind, CapabilityState};
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
    let file = File::open(path).map_err(|source| CaptureEventFeedLoadError::OpenFile {
        path: path.display().to_string(),
        source,
    })?;
    Ok(JsonLinesCaptureEventFeedProvider::new(
        BufReader::new(file),
        path.display().to_string(),
        follow,
    ))
}

#[derive(Debug)]
pub(crate) struct JsonLinesCaptureEventFeedProvider<R> {
    reader: JsonLinesReader<R>,
    follow: bool,
}

impl<R> JsonLinesCaptureEventFeedProvider<R>
where
    R: BufRead,
{
    fn new(reader: R, path: impl Into<String>, follow: bool) -> Self {
        Self {
            reader: JsonLinesReader::new(
                reader,
                path,
                "capture event feed",
                MAX_CAPTURE_EVENT_FEED_LINE_BYTES,
            ),
            follow,
        }
    }

    fn read_next_poll(&mut self) -> Result<CapturePoll, crate::json_lines::JsonLinesError> {
        let eof = if self.follow {
            JsonLinesEof::Follow
        } else {
            JsonLinesEof::Finish
        };
        match self.reader.read::<CaptureEvent>(eof)? {
            JsonLinesRead::Item(event) => Ok(CapturePoll::event(event)),
            JsonLinesRead::Idle => Ok(CapturePoll::Idle),
            JsonLinesRead::Finished => Ok(CapturePoll::Finished),
        }
    }
}

impl<R> CaptureProvider for JsonLinesCaptureEventFeedProvider<R>
where
    R: BufRead,
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
    use std::io::Cursor;

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
        let reason = "deterministic provider loss fixture".to_string();
        CaptureEvent::Loss(CapturedLoss {
            timestamp: Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 2,
            },
            origin: CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
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
}
