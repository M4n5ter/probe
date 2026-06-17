use crate::CaptureError;

use super::{
    EbpfProcessObservation, EbpfProcessObservationProbe,
    payload_authorization::SocketPayloadSampleAuthorization,
};

pub(super) trait EbpfObservationSource {
    fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError>;

    fn allow_socket_payload_sample(
        &mut self,
        authorization: SocketPayloadSampleAuthorization,
    ) -> Result<(), CaptureError>;

    fn process_output_loss_count(&mut self) -> Result<u64, CaptureError> {
        Ok(0)
    }
}

pub(super) struct ProbeObservationSource {
    pub(super) probe: EbpfProcessObservationProbe,
}

impl EbpfObservationSource for ProbeObservationSource {
    fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
        self.probe
            .next_observation()
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))
    }

    fn allow_socket_payload_sample(
        &mut self,
        authorization: SocketPayloadSampleAuthorization,
    ) -> Result<(), CaptureError> {
        self.probe
            .allow_socket_payload_sample(
                authorization.tgid(),
                authorization.fd(),
                authorization.fd_table_epoch(),
                authorization.payload_directions().to_abi_mask(),
            )
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))
    }

    fn process_output_loss_count(&mut self) -> Result<u64, CaptureError> {
        self.probe
            .process_output_loss_count()
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))
    }
}
