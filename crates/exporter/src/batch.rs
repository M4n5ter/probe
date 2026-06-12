use async_trait::async_trait;
use proto::BatchEnvelope;

use crate::{ExportAck, ExportError};

#[async_trait]
pub trait BatchExporter {
    async fn send_batch(&self, batch: &BatchEnvelope) -> Result<ExportAck, ExportError>;
}
