use crate::{CaptureError, EbpfProcessObservationTracepointFiring};

use super::{
    EbpfProcessObservation, EbpfProcessObservationProbe, descriptor_lease::DescriptorLeaseKey,
    payload_authorization::SocketPayloadSampleAuthorization,
};

pub(super) trait EbpfObservationSource {
    fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError>;

    fn allow_socket_payload_sample(
        &mut self,
        authorization: SocketPayloadSampleAuthorization,
    ) -> Result<(), CaptureError>;

    fn revoke_socket_payload_sample(
        &mut self,
        _key: DescriptorLeaseKey,
    ) -> Result<(), CaptureError> {
        Ok(())
    }

    fn process_output_loss_count(&mut self) -> Result<u64, CaptureError> {
        Ok(0)
    }

    fn process_tracepoint_firings(
        &mut self,
    ) -> Result<Option<Vec<EbpfProcessObservationTracepointFiring>>, CaptureError> {
        Ok(None)
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
            .allow_socket_payload_sample(authorization)
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))
    }

    fn revoke_socket_payload_sample(
        &mut self,
        key: DescriptorLeaseKey,
    ) -> Result<(), CaptureError> {
        self.probe
            .revoke_socket_payload_sample(key)
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))
    }

    fn process_output_loss_count(&mut self) -> Result<u64, CaptureError> {
        self.probe
            .process_output_loss_count()
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))
    }

    fn process_tracepoint_firings(
        &mut self,
    ) -> Result<Option<Vec<EbpfProcessObservationTracepointFiring>>, CaptureError> {
        self.probe
            .process_tracepoint_firings()
            .map(Some)
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))
    }
}
