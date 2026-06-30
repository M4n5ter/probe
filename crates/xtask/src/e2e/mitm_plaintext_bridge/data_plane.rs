use std::borrow::Cow;

use e2e_support::mitm_bridge;

use super::{
    case::{MitmBridgeCase, MitmDataPlaneExercise},
    tls, websocket,
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
            MitmDataPlaneExercise::ProductProxyTransparentTls { .. }
                | MitmDataPlaneExercise::ProductProxyTransparentTlsWebSocket { .. }
        )
    }

    pub(super) const fn protocol(self) -> MitmDataPlaneProtocol {
        match self.exercise {
            MitmDataPlaneExercise::ProductProxyTransparentTlsWebSocket { .. } => {
                MitmDataPlaneProtocol::WebSocket
            }
            MitmDataPlaneExercise::None
            | MitmDataPlaneExercise::ManagedPlaintext
            | MitmDataPlaneExercise::ProductProxyTransparentTls { .. } => {
                MitmDataPlaneProtocol::BridgeHttp
            }
        }
    }

    pub(super) const fn server_name(self) -> &'static str {
        match self.exercise.product_proxy_server_name() {
            Some(server_name) => server_name,
            None => tls::SERVER_NAME,
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
            MitmDataPlaneProtocol::BridgeHttp => {
                mitm_bridge::request_bytes_for_host(self.server_name())
            }
            MitmDataPlaneProtocol::WebSocket => {
                Cow::Owned(websocket::upgrade_request_bytes(self.server_name()))
            }
        }
    }

    pub(super) fn allow_request_bytes(self) -> Cow<'static, [u8]> {
        mitm_bridge::allow_request_bytes_for_host(self.server_name())
    }
}
