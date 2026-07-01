use std::{
    fmt,
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
};

use super::{NetlinkSocketDestroy, SOCKET_DESTROY_TIMEOUT, SocketDestroy, SocketDestroyRequest};

#[derive(Debug)]
struct LoopbackKillSelfTestResult {
    kill: super::SocketDestroyOutcome,
    connection_probe: ConnectionProbeOutcome,
}

fn run_loopback_kill_self_test() -> io::Result<LoopbackKillSelfTestResult> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let target = listener.local_addr()?;
    let mut client = TcpStream::connect(target)?;
    let (mut server, _peer) = listener.accept()?;
    client.set_read_timeout(Some(SOCKET_DESTROY_TIMEOUT))?;
    client.set_write_timeout(Some(SOCKET_DESTROY_TIMEOUT))?;
    server.set_read_timeout(Some(SOCKET_DESTROY_TIMEOUT))?;
    server.set_write_timeout(Some(SOCKET_DESTROY_TIMEOUT))?;

    let client_addr = client.local_addr()?;
    let request = SocketDestroyRequest {
        local_address: client_addr.ip(),
        local_port: client_addr.port(),
        remote_address: target.ip(),
        remote_port: target.port(),
    };
    let kill = NetlinkSocketDestroy::new().destroy(&request)?;
    let connection_probe = probe_connection_after_kill(&mut client, &mut server)?;
    drop(server);
    drop(client);
    Ok(LoopbackKillSelfTestResult {
        kill,
        connection_probe,
    })
}

pub(super) fn check_loopback_socket_destroy_support() -> Result<(), String> {
    let result = run_loopback_kill_self_test().map_err(|error| {
        format!("failed to run netlink SOCK_DESTROY loopback self-test: {error}")
    })?;
    if !loopback_kill_self_test_proves_destroy(&result) {
        return Err(loopback_kill_self_test_failure(&result));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionProbeOutcome {
    Interrupted,
    Alive,
    Inconclusive {
        operation: ConnectionProbeOperation,
        error_kind: io::ErrorKind,
    },
}

impl fmt::Display for ConnectionProbeOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupted => formatter.write_str("interrupted"),
            Self::Alive => formatter.write_str("alive"),
            Self::Inconclusive {
                operation,
                error_kind,
            } => write!(formatter, "inconclusive({operation}: {error_kind:?})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionProbeOperation {
    Write,
    Read,
}

impl fmt::Display for ConnectionProbeOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write => formatter.write_str("write"),
            Self::Read => formatter.write_str("read"),
        }
    }
}

fn probe_connection_after_kill(
    client: &mut impl Write,
    server: &mut impl Read,
) -> io::Result<ConnectionProbeOutcome> {
    const PROBE: &[u8] = b"traffic-probe-socket-destroy-self-test";
    match client.write_all(PROBE) {
        Ok(()) => {}
        Err(error) => return socket_probe_error_outcome(ConnectionProbeOperation::Write, error),
    }

    let mut received = [0_u8; PROBE.len()];
    match server.read(&mut received) {
        Ok(0) => Ok(ConnectionProbeOutcome::Interrupted),
        Ok(_) => Ok(ConnectionProbeOutcome::Alive),
        Err(error) => socket_probe_error_outcome(ConnectionProbeOperation::Read, error),
    }
}

fn socket_probe_error_outcome(
    operation: ConnectionProbeOperation,
    error: io::Error,
) -> io::Result<ConnectionProbeOutcome> {
    if is_socket_interruption_error(&error) {
        Ok(ConnectionProbeOutcome::Interrupted)
    } else if is_inconclusive_socket_probe_error(&error) {
        Ok(ConnectionProbeOutcome::Inconclusive {
            operation,
            error_kind: error.kind(),
        })
    } else {
        Err(error)
    }
}

fn is_socket_interruption_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
    )
}

fn is_inconclusive_socket_probe_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn loopback_kill_self_test_failure(result: &LoopbackKillSelfTestResult) -> String {
    format!(
        "netlink SOCK_DESTROY loopback self-test did not prove socket destroy: reported_destroy={}, connection_probe={}",
        matches!(result.kill, super::SocketDestroyOutcome::Destroyed { .. }),
        result.connection_probe,
    )
}

fn loopback_kill_self_test_proves_destroy(result: &LoopbackKillSelfTestResult) -> bool {
    matches!(result.kill, super::SocketDestroyOutcome::Destroyed { .. })
        && matches!(result.connection_probe, ConnectionProbeOutcome::Interrupted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_connection_after_kill_reports_alive_socket_pair() -> io::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let target = listener.local_addr()?;
        let mut client = TcpStream::connect(target)?;
        let (mut server, _peer) = listener.accept()?;
        client.set_read_timeout(Some(SOCKET_DESTROY_TIMEOUT))?;
        client.set_write_timeout(Some(SOCKET_DESTROY_TIMEOUT))?;
        server.set_read_timeout(Some(SOCKET_DESTROY_TIMEOUT))?;
        server.set_write_timeout(Some(SOCKET_DESTROY_TIMEOUT))?;

        assert_eq!(
            probe_connection_after_kill(&mut client, &mut server)?,
            ConnectionProbeOutcome::Alive
        );
        Ok(())
    }

    #[test]
    fn probe_connection_after_kill_reports_closed_socket_as_interrupted() -> io::Result<()> {
        let mut writer = FailingWriter(io::ErrorKind::BrokenPipe);
        let mut reader = io::empty();

        assert_eq!(
            probe_connection_after_kill(&mut writer, &mut reader)?,
            ConnectionProbeOutcome::Interrupted
        );
        Ok(())
    }

    #[test]
    fn probe_connection_after_kill_reports_timeout_as_inconclusive() -> io::Result<()> {
        let mut timeout_writer = FailingWriter(io::ErrorKind::WouldBlock);
        let mut unused_reader = io::empty();
        assert_eq!(
            probe_connection_after_kill(&mut timeout_writer, &mut unused_reader)?,
            ConnectionProbeOutcome::Inconclusive {
                operation: ConnectionProbeOperation::Write,
                error_kind: io::ErrorKind::WouldBlock,
            }
        );

        let mut writer = Vec::new();
        let mut timeout_reader = FailingReader(io::ErrorKind::TimedOut);
        assert_eq!(
            probe_connection_after_kill(&mut writer, &mut timeout_reader)?,
            ConnectionProbeOutcome::Inconclusive {
                operation: ConnectionProbeOperation::Read,
                error_kind: io::ErrorKind::TimedOut,
            }
        );
        Ok(())
    }

    #[test]
    fn loopback_self_test_requires_reported_destroy_and_interrupted_connection() {
        let destroyed = LoopbackKillSelfTestResult {
            kill: socket_destroy_result(1),
            connection_probe: ConnectionProbeOutcome::Interrupted,
        };
        assert!(loopback_kill_self_test_proves_destroy(&destroyed));

        let missing_report = LoopbackKillSelfTestResult {
            kill: socket_destroy_result(0),
            connection_probe: ConnectionProbeOutcome::Interrupted,
        };
        assert!(!loopback_kill_self_test_proves_destroy(&missing_report));
        assert!(
            loopback_kill_self_test_failure(&missing_report).contains("reported_destroy=false")
        );

        let live_connection = LoopbackKillSelfTestResult {
            kill: socket_destroy_result(1),
            connection_probe: ConnectionProbeOutcome::Alive,
        };
        assert!(!loopback_kill_self_test_proves_destroy(&live_connection));
        assert!(
            loopback_kill_self_test_failure(&live_connection).contains("connection_probe=alive")
        );

        let inconclusive_connection = LoopbackKillSelfTestResult {
            kill: socket_destroy_result(1),
            connection_probe: ConnectionProbeOutcome::Inconclusive {
                operation: ConnectionProbeOperation::Read,
                error_kind: io::ErrorKind::TimedOut,
            },
        };
        assert!(!loopback_kill_self_test_proves_destroy(
            &inconclusive_connection
        ));
        assert!(
            loopback_kill_self_test_failure(&inconclusive_connection)
                .contains("connection_probe=inconclusive(read: TimedOut)")
        );
    }

    fn socket_destroy_result(destroyed_socket_count: usize) -> super::super::SocketDestroyOutcome {
        if destroyed_socket_count == 0 {
            super::super::SocketDestroyOutcome::NoMatchingSocket
        } else {
            super::super::SocketDestroyOutcome::Destroyed {
                count: destroyed_socket_count,
            }
        }
    }

    struct FailingWriter(io::ErrorKind);

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingReader(io::ErrorKind);

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
    }
}
