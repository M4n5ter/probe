use std::{
    io::{self, Read, Write},
    thread,
    time::Duration,
};

use probe_core::{Direction, FlowContext};

use crate::{
    MitmProxyError,
    error::io_error,
    feed::{CaptureEventFeedWriter, FlowOffsets},
};

use super::{downstream::DownstreamStream, response_direction, upstream::UpstreamConnection};

const TUNNEL_BUFFER_BYTES: usize = 16 * 1024;
const TUNNEL_POLL_TIMEOUT: Duration = Duration::from_millis(20);

pub(super) fn relay_upgraded_tunnel(
    downstream: &mut DownstreamStream,
    upstream: &mut UpstreamConnection,
    feed: &CaptureEventFeedWriter,
    flow: &FlowContext,
    offsets: &mut FlowOffsets,
    request_direction: Direction,
    initial_downstream_bytes: &[u8],
) -> Result<(), MitmProxyError> {
    downstream.set_read_timeout(Some(TUNNEL_POLL_TIMEOUT))?;
    upstream.set_read_timeout(Some(TUNNEL_POLL_TIMEOUT))?;

    let response_direction = response_direction(request_direction);
    let mut context = TunnelRelay {
        feed,
        flow,
        offsets,
    };
    let downstream_leg = TunnelLeg {
        direction: request_direction,
        read_action: "read MITM proxy upgraded downstream bytes",
        write_action: "write MITM proxy upgraded upstream bytes",
    };
    let upstream_leg = TunnelLeg {
        direction: response_direction,
        read_action: "read MITM proxy upgraded upstream bytes",
        write_action: "write MITM proxy upgraded downstream bytes",
    };
    forward_bytes(
        upstream,
        &mut context,
        downstream_leg,
        initial_downstream_bytes,
    )?;
    let mut downstream_buffer = [0_u8; TUNNEL_BUFFER_BYTES];
    let mut upstream_buffer = [0_u8; TUNNEL_BUFFER_BYTES];
    let mut downstream_state = LegState::Open;
    let mut upstream_state = LegState::Open;

    loop {
        let downstream_progress = if downstream_state == LegState::Open {
            relay_once(
                downstream,
                upstream,
                &mut context,
                downstream_leg,
                &mut downstream_buffer,
            )?
        } else {
            TunnelProgress::Idle
        };
        if downstream_progress == TunnelProgress::Closed {
            downstream_state = LegState::ReadClosed;
            upstream.shutdown_write()?;
        }

        let upstream_progress = if upstream_state == LegState::Open {
            relay_once(
                upstream,
                downstream,
                &mut context,
                upstream_leg,
                &mut upstream_buffer,
            )?
        } else {
            TunnelProgress::Idle
        };
        if upstream_progress == TunnelProgress::Closed {
            upstream_state = LegState::ReadClosed;
            downstream.shutdown_write()?;
        }

        if downstream_state == LegState::ReadClosed && upstream_state == LegState::ReadClosed {
            return Ok(());
        }
        if matches!(
            (downstream_progress, upstream_progress),
            (TunnelProgress::Idle, TunnelProgress::Idle)
        ) {
            thread::sleep(TUNNEL_POLL_TIMEOUT);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegState {
    Open,
    ReadClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TunnelProgress {
    Data,
    Idle,
    Closed,
}

struct TunnelRelay<'a> {
    feed: &'a CaptureEventFeedWriter,
    flow: &'a FlowContext,
    offsets: &'a mut FlowOffsets,
}

#[derive(Clone, Copy)]
struct TunnelLeg {
    direction: Direction,
    read_action: &'static str,
    write_action: &'static str,
}

fn relay_once(
    source: &mut impl Read,
    destination: &mut impl Write,
    context: &mut TunnelRelay<'_>,
    leg: TunnelLeg,
    buffer: &mut [u8],
) -> Result<TunnelProgress, MitmProxyError> {
    let read = match source.read(buffer) {
        Ok(0) => return Ok(TunnelProgress::Closed),
        Ok(read) => read,
        Err(error) if is_temporary_read_idle(&error) => return Ok(TunnelProgress::Idle),
        Err(error) => return Err(io_error(leg.read_action)(error)),
    };
    let bytes = &buffer[..read];
    forward_bytes(destination, context, leg, bytes)?;
    Ok(TunnelProgress::Data)
}

fn forward_bytes(
    destination: &mut impl Write,
    context: &mut TunnelRelay<'_>,
    leg: TunnelLeg,
    bytes: &[u8],
) -> Result<(), MitmProxyError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let offset = context.offsets.record(leg.direction, bytes.len());
    context
        .feed
        .bytes(context.flow, leg.direction, offset, bytes)?;
    destination
        .write_all(bytes)
        .map_err(io_error(leg.write_action))?;
    destination.flush().map_err(io_error(leg.write_action))
}

fn is_temporary_read_idle(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
