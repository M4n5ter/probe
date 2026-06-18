use crate::{CaptureEvent, PlaintextConnection, PlaintextEvent, PlaintextSource};

use super::{Tls13SessionSecretCaptureDisposition, Tls13SessionSecretDecryptingProvider};

impl Tls13SessionSecretDecryptingProvider {
    pub(super) fn ensure_plaintext_close_for_bound_capture_close(
        &self,
        event: &CaptureEvent,
        disposition: &Tls13SessionSecretCaptureDisposition,
        plaintext_events: &mut Vec<PlaintextEvent>,
    ) {
        let (
            CaptureEvent::ConnectionClosed {
                timestamp, flow, ..
            },
            Tls13SessionSecretCaptureDisposition::BoundFlow(_),
        ) = (event, disposition)
        else {
            return;
        };
        let carrying_gaps = self
            .flow_registry
            .observation_only_gaps_before_plaintext_finalization(
                flow,
                *timestamp,
                plaintext_events,
            );
        plaintext_events.extend(carrying_gaps);
        plaintext_events.push(PlaintextEvent::connection_closed(
            PlaintextSource::TlsSessionSecret,
            PlaintextConnection::new(*timestamp, flow.clone()),
        ));
    }
}
