use std::borrow::Cow;

use e2e_support::mitm_bridge;

use super::{
    backend::{MitmBridgeCase, MitmDataPlaneExercise},
    websocket,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmDataPlaneProtocol {
    BridgeHttp,
    WebSocket,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MitmDataPlaneScenario {
    exercise: MitmDataPlaneExercise,
}

pub(super) fn scenario(case: MitmBridgeCase) -> MitmDataPlaneScenario {
    MitmDataPlaneScenario {
        exercise: case.spec().data_plane,
    }
}

impl MitmDataPlaneScenario {
    pub(super) const fn is_none(self) -> bool {
        matches!(self.exercise, MitmDataPlaneExercise::None)
    }

    pub(super) const fn is_managed_plaintext(self) -> bool {
        matches!(self.exercise, MitmDataPlaneExercise::ManagedPlaintext)
    }

    pub(super) const fn uses_product_proxy_transparent_tls(self) -> bool {
        matches!(
            self.exercise,
            MitmDataPlaneExercise::ProductProxyTransparentTls
                | MitmDataPlaneExercise::ProductProxyTransparentTlsWebSocket
        )
    }

    pub(super) const fn protocol(self) -> MitmDataPlaneProtocol {
        match self.exercise {
            MitmDataPlaneExercise::ProductProxyTransparentTlsWebSocket => {
                MitmDataPlaneProtocol::WebSocket
            }
            MitmDataPlaneExercise::None
            | MitmDataPlaneExercise::ManagedPlaintext
            | MitmDataPlaneExercise::ProductProxyTransparentTls => {
                MitmDataPlaneProtocol::BridgeHttp
            }
        }
    }

    pub(super) fn request_target(self) -> &'static str {
        match self.protocol() {
            MitmDataPlaneProtocol::BridgeHttp => mitm_bridge::REQUEST_TARGET,
            MitmDataPlaneProtocol::WebSocket => websocket::TARGET,
        }
    }

    pub(super) fn request_bytes(self) -> Cow<'static, [u8]> {
        match self.protocol() {
            MitmDataPlaneProtocol::BridgeHttp => Cow::Borrowed(mitm_bridge::REQUEST_BYTES),
            MitmDataPlaneProtocol::WebSocket => Cow::Owned(websocket::upgrade_request_bytes()),
        }
    }
}
