use probe_core::{
    AddressPort, CaptureOrigin, CaptureSource, EventEnvelope, EventKind, FlowContext, FlowIdentity,
    ProcessContext, ProcessIdentity, SpoolPayloadSchema, Timestamp, TransportProtocol,
};
use storage::{FjallSpool, SpoolPayload};

pub(in crate::export::drain) fn append_export_events(
    spool: &FjallSpool,
    count: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    for sequence in 1..=count {
        append_export_event(spool, sequence)?;
    }
    Ok(())
}

pub(in crate::export::drain) fn append_export_event(
    spool: &FjallSpool,
    monotonic_ns: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = EventEnvelope::from_flow(
        current_timestamp(monotonic_ns),
        replay_flow(),
        CaptureOrigin::from_source(CaptureSource::Replay),
        "test",
        EventKind::ConnectionOpened,
    );
    let payload = serde_json::to_vec(&envelope)?;
    spool.append_export(SpoolPayload::new(
        SpoolPayloadSchema::EventEnvelopeSubjectOriginJson,
        payload,
    ))?;
    Ok(())
}

fn current_timestamp(monotonic_ns: u64) -> Timestamp {
    Timestamp {
        monotonic_ns,
        wall_time_unix_ns: 1,
    }
}

fn replay_flow() -> FlowContext {
    let process = synthetic_replay_process();
    let local = AddressPort {
        address: "127.0.0.1".to_string(),
        port: 50_000,
    };
    let remote = AddressPort {
        address: "127.0.0.1".to_string(),
        port: 80,
    };
    FlowContext {
        id: FlowIdentity::stable(
            &process.identity,
            &local,
            &remote,
            TransportProtocol::Tcp,
            0,
            None,
        ),
        process,
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns: 0,
        socket_cookie: None,
        attribution_confidence: 0,
    }
}

fn synthetic_replay_process() -> ProcessContext {
    let identity = ProcessIdentity {
        pid: 0,
        tgid: 0,
        start_time_ticks: 0,
        boot_id: "replay".to_string(),
        exe_path: "replay".to_string(),
        cmdline_hash: "replay".to_string(),
        uid: 0,
        gid: 0,
        cgroup: None,
        systemd_service: None,
        container_id: None,
        runtime_hint: None,
    };
    ProcessContext {
        identity,
        name: "replay".to_string(),
        cmdline: vec!["replay".to_string()],
    }
}
