use probe_core::{EventEnvelope, SpoolPayloadSchema};
use storage::{AppendOutcome, DurableSpool, SpoolPayload};
use thiserror::Error;

use crate::runtime_metrics::PipelineRuntimeMetrics;

#[derive(Debug, Error)]
pub enum ExportEventWriteError {
    #[error("failed to serialize export event envelope: {0}")]
    Json(#[from] serde_json::Error),
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
}

pub struct ExportEventWriter<'a, S> {
    spool: &'a S,
    metrics: Option<PipelineRuntimeMetrics>,
}

impl<'a, S> ExportEventWriter<'a, S>
where
    S: DurableSpool,
{
    pub fn new(spool: &'a S) -> Self {
        Self {
            spool,
            metrics: None,
        }
    }

    pub fn with_runtime_metrics(mut self, metrics: Option<PipelineRuntimeMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn append_once(&self, envelope: &EventEnvelope) -> Result<bool, ExportEventWriteError> {
        let payload = envelope_payload(envelope)?;
        let outcome = self.spool.append_export_once(
            envelope.id().as_str(),
            SpoolPayload::new(SpoolPayloadSchema::EventEnvelopeSubjectOriginJson, payload),
        )?;
        let appended = matches!(outcome, AppendOutcome::Appended(_));
        if appended {
            self.record_written();
        }
        Ok(appended)
    }

    pub fn append_occurrence(&self, envelope: &EventEnvelope) -> Result<(), ExportEventWriteError> {
        let payload = envelope_payload(envelope)?;
        self.spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
            payload,
        ))?;
        self.record_written();
        Ok(())
    }

    fn record_written(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_export_event_written();
        }
    }
}

fn envelope_payload(envelope: &EventEnvelope) -> Result<Vec<u8>, ExportEventWriteError> {
    serde_json::to_vec(envelope).map_err(ExportEventWriteError::Json)
}
