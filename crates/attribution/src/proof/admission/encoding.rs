use blake3::Hasher;

use super::super::{AttributionScope, TargetBinding};
use super::CaptureGrant;
use probe_core::TimeInterval;

pub(super) fn hash_scope(hasher: &mut Hasher, scope: AttributionScope) {
    hasher.update(scope.boot().as_bytes());
    hasher.update(scope.network_namespace().as_bytes());
    hasher.update(scope.capture_stage().as_bytes());
}

pub(super) fn hash_binding(hasher: &mut Hasher, binding: TargetBinding) {
    match binding.workload() {
        Some(workload) => {
            hasher.update(&[1]);
            hasher.update(workload.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match binding.process() {
        Some(process) => {
            hasher.update(&[1]);
            hasher.update(process.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

pub(super) fn hash_capture_grant(hasher: &mut Hasher, grant: CaptureGrant) {
    let payload = match grant.payload() {
        super::PayloadAccess::MetadataOnly => 0,
        super::PayloadAccess::FullPayload => 1,
    };
    let completeness = match grant.completeness() {
        super::CompletenessAllowance::RequireComplete => 0,
        super::CompletenessAllowance::AllowIncomplete => 1,
    };
    hasher.update(&[payload, completeness]);
    hasher.update(&grant.retention().max_age_ns().to_be_bytes());
    hasher.update(&grant.retention().max_bytes().to_be_bytes());
}

pub(super) fn hash_interval(hasher: &mut Hasher, interval: TimeInterval) {
    hasher.update(&interval.start().as_nanos().to_be_bytes());
    hasher.update(&interval.end().as_nanos().to_be_bytes());
}
