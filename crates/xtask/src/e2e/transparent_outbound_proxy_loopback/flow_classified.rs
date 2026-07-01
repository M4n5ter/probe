use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use super::{
    CLIENT_PAYLOAD, FLOW_CLASSIFIER_REJECTED_PORT, LOOPBACK_ADDR, OutboundProxyE2eCase,
    SERVER_RESPONSE,
};
use crate::e2e::harness::e2e_error;

const REJECTED_UPSTREAM_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) struct RejectedUpstreamProbe {
    listener: TcpListener,
}

impl RejectedUpstreamProbe {
    pub(super) fn bind_for_case(
        case: OutboundProxyE2eCase,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        if !case.is_flow_classified() {
            return Ok(None);
        }
        let listener = TcpListener::bind((LOOPBACK_ADDR, FLOW_CLASSIFIER_REJECTED_PORT))?;
        listener.set_nonblocking(true)?;
        Ok(Some(Self { listener }))
    }

    fn assert_no_accept(self) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + REJECTED_UPSTREAM_ACCEPT_TIMEOUT;
        loop {
            match self.listener.accept() {
                Ok((stream, peer_addr)) => {
                    drop(stream);
                    return Err(e2e_error(format!(
                        "flow-classified rejected outbound branch unexpectedly reached upstream from {peer_addr}"
                    ))
                    .into());
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

pub(super) fn assert_rejected_client_for_case(
    case: OutboundProxyE2eCase,
) -> Result<(), Box<dyn std::error::Error>> {
    if !case.is_flow_classified() {
        return Ok(());
    }

    let mut stream = TcpStream::connect((LOOPBACK_ADDR, FLOW_CLASSIFIER_REJECTED_PORT))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    if let Err(error) = stream.write_all(CLIENT_PAYLOAD) {
        return if is_expected_close_error(error.kind()) {
            Ok(())
        } else {
            Err(error.into())
        };
    }

    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) if response.is_empty() => Ok(()),
        Ok(_) if response == SERVER_RESPONSE => Err(e2e_error(
            "flow-classified rejected outbound branch unexpectedly received upstream response",
        )
        .into()),
        Ok(_) => Err(e2e_error(format!(
            "flow-classified rejected outbound branch received unexpected response: {:?}",
            String::from_utf8_lossy(&response)
        ))
        .into()),
        Err(error) if response.is_empty() && is_expected_close_error(error.kind()) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn assert_rejected_upstream_for_case(
    rejected_upstream: Option<RejectedUpstreamProbe>,
) -> Result<(), Box<dyn std::error::Error>> {
    match rejected_upstream {
        Some(probe) => probe.assert_no_accept(),
        None => Ok(()),
    }
}

fn is_expected_close_error(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionReset
            | ErrorKind::UnexpectedEof
            | ErrorKind::NotConnected
    )
}
