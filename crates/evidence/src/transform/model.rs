use std::{fmt, num::NonZeroU64};

use crate::{ByteExtentRef, ContentDigest, TransformId};

use super::page::MappingManifestRef;

pub const MAPPING_SPAN_MAX_ARITY: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransformRevision(ContentDigest);

impl TransformRevision {
    pub const fn new(digest: ContentDigest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> ContentDigest {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransformKind {
    Reassembly,
    Decrypt,
    ProxyForward,
    Demultiplex,
    TransferDecode,
    ContentDecode,
    Presentation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityIssueSetRef {
    root: ContentDigest,
    issue_count: NonZeroU64,
}

impl IntegrityIssueSetRef {
    pub const fn new(root: ContentDigest, issue_count: NonZeroU64) -> Self {
        Self { root, issue_count }
    }

    pub const fn root(self) -> ContentDigest {
        self.root
    }

    pub const fn issue_count(self) -> NonZeroU64 {
        self.issue_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransformIntegrity {
    Complete,
    Partial(IntegrityIssueSetRef),
    Ambiguous(IntegrityIssueSetRef),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingRelation {
    Exact,
    ManyToMany,
    Irreversible,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MappingSide {
    Inputs,
    Outputs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentSetRef {
    root: ContentDigest,
    mapping_manifest: ContentDigest,
    side: MappingSide,
    extent_count: NonZeroU64,
}

impl ExtentSetRef {
    pub fn from_manifest_parts(
        manifest: MappingManifestRef,
        side: MappingSide,
        root: ContentDigest,
        extent_count: NonZeroU64,
    ) -> Result<Self, TransformMappingError> {
        let expected = Self::for_mapping(manifest, side);
        let candidate = Self {
            root,
            mapping_manifest: manifest.digest(),
            side,
            extent_count,
        };
        if candidate != expected {
            return Err(TransformMappingError::ExtentSetMismatch(side));
        }
        Ok(candidate)
    }

    pub const fn root(self) -> ContentDigest {
        self.root
    }

    pub const fn mapping_manifest(self) -> ContentDigest {
        self.mapping_manifest
    }

    pub const fn side(self) -> MappingSide {
        self.side
    }

    pub const fn extent_count(self) -> NonZeroU64 {
        self.extent_count
    }

    pub(crate) fn for_mapping(manifest: MappingManifestRef, side: MappingSide) -> Self {
        let extent_count = match side {
            MappingSide::Inputs => manifest.summary().input_extent_count(),
            MappingSide::Outputs => manifest.summary().output_extent_count(),
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"probe-evidence-mapped-extent-set\0");
        hasher.update(manifest.digest().as_bytes());
        hasher.update(&[mapping_side_tag(side)]);
        hasher.update(&extent_count.get().to_be_bytes());
        Self {
            root: ContentDigest::new(*hasher.finalize().as_bytes()),
            mapping_manifest: manifest.digest(),
            side,
            extent_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingSpan {
    relation: MappingRelation,
    inputs: Box<[ByteExtentRef]>,
    outputs: Box<[ByteExtentRef]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingError {
    EmptySide,
    ArityExceeded,
    ExactCardinalityMismatch,
    ExactLengthMismatch,
}

impl fmt::Display for MappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptySide => "transform mapping requires input and output extents",
            Self::ArityExceeded => "transform mapping span exceeds its fixed arity",
            Self::ExactCardinalityMismatch => {
                "exact transform mapping requires equal input and output cardinality"
            }
            Self::ExactLengthMismatch => {
                "exact transform mapping requires equal paired extent lengths"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for MappingError {}

impl MappingSpan {
    pub fn new(
        relation: MappingRelation,
        inputs: Vec<ByteExtentRef>,
        outputs: Vec<ByteExtentRef>,
    ) -> Result<Self, MappingError> {
        validate_mapping(relation, &inputs, &outputs)?;
        Ok(Self {
            relation,
            inputs: inputs.into_boxed_slice(),
            outputs: outputs.into_boxed_slice(),
        })
    }

    pub fn validate(&self) -> Result<(), MappingError> {
        validate_mapping(self.relation, &self.inputs, &self.outputs)
    }

    pub const fn relation(&self) -> MappingRelation {
        self.relation
    }

    pub fn inputs(&self) -> &[ByteExtentRef] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[ByteExtentRef] {
        &self.outputs
    }

    pub const fn supports_exact_reverse_lookup(&self) -> bool {
        matches!(self.relation, MappingRelation::Exact)
    }

    pub(crate) fn into_extents(self, side: MappingSide) -> Box<[ByteExtentRef]> {
        match side {
            MappingSide::Inputs => self.inputs,
            MappingSide::Outputs => self.outputs,
        }
    }
}

fn validate_mapping(
    relation: MappingRelation,
    inputs: &[ByteExtentRef],
    outputs: &[ByteExtentRef],
) -> Result<(), MappingError> {
    if inputs.is_empty() || outputs.is_empty() {
        return Err(MappingError::EmptySide);
    }
    if inputs.len() > MAPPING_SPAN_MAX_ARITY || outputs.len() > MAPPING_SPAN_MAX_ARITY {
        return Err(MappingError::ArityExceeded);
    }
    if relation == MappingRelation::Exact {
        if inputs.len() != outputs.len() {
            return Err(MappingError::ExactCardinalityMismatch);
        }
        if inputs
            .iter()
            .zip(outputs)
            .any(|(input, output)| input.range.length() != output.range.length())
        {
            return Err(MappingError::ExactLengthMismatch);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransformMapping {
    manifest: MappingManifestRef,
    inputs: ExtentSetRef,
    outputs: ExtentSetRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransformMappingError {
    ExtentSetMismatch(MappingSide),
}

impl fmt::Display for TransformMappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExtentSetMismatch(MappingSide::Inputs) => {
                formatter.write_str("input extent set is not bound to the mapping manifest")
            }
            Self::ExtentSetMismatch(MappingSide::Outputs) => {
                formatter.write_str("output extent set is not bound to the mapping manifest")
            }
        }
    }
}

impl std::error::Error for TransformMappingError {}

impl TransformMapping {
    pub fn from_parts(
        manifest: MappingManifestRef,
        inputs: ExtentSetRef,
        outputs: ExtentSetRef,
    ) -> Result<Self, TransformMappingError> {
        if inputs != ExtentSetRef::for_mapping(manifest, MappingSide::Inputs) {
            return Err(TransformMappingError::ExtentSetMismatch(
                MappingSide::Inputs,
            ));
        }
        if outputs != ExtentSetRef::for_mapping(manifest, MappingSide::Outputs) {
            return Err(TransformMappingError::ExtentSetMismatch(
                MappingSide::Outputs,
            ));
        }
        Ok(Self {
            manifest,
            inputs,
            outputs,
        })
    }

    pub const fn manifest(self) -> MappingManifestRef {
        self.manifest
    }

    pub const fn inputs(self) -> ExtentSetRef {
        self.inputs
    }

    pub const fn outputs(self) -> ExtentSetRef {
        self.outputs
    }

    pub(crate) fn for_manifest(manifest: MappingManifestRef) -> Self {
        Self {
            manifest,
            inputs: ExtentSetRef::for_mapping(manifest, MappingSide::Inputs),
            outputs: ExtentSetRef::for_mapping(manifest, MappingSide::Outputs),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransformEdge {
    id: TransformId,
    kind: TransformKind,
    revision: TransformRevision,
    mapping: TransformMapping,
    integrity: TransformIntegrity,
}

impl TransformEdge {
    pub const fn new(
        id: TransformId,
        kind: TransformKind,
        revision: TransformRevision,
        mapping: TransformMapping,
        integrity: TransformIntegrity,
    ) -> Self {
        Self {
            id,
            kind,
            revision,
            mapping,
            integrity,
        }
    }

    pub const fn id(self) -> TransformId {
        self.id
    }

    pub const fn kind(self) -> TransformKind {
        self.kind
    }

    pub const fn revision(self) -> TransformRevision {
        self.revision
    }

    pub const fn mapping(self) -> TransformMapping {
        self.mapping
    }

    pub const fn inputs(self) -> ExtentSetRef {
        self.mapping.inputs()
    }

    pub const fn outputs(self) -> ExtentSetRef {
        self.mapping.outputs()
    }

    pub const fn integrity(self) -> TransformIntegrity {
        self.integrity
    }
}

pub(crate) const fn mapping_relation_tag(relation: MappingRelation) -> u8 {
    match relation {
        MappingRelation::Exact => 0,
        MappingRelation::ManyToMany => 1,
        MappingRelation::Irreversible => 2,
    }
}

const fn mapping_side_tag(side: MappingSide) -> u8 {
    match side {
        MappingSide::Inputs => 0,
        MappingSide::Outputs => 1,
    }
}

#[cfg(test)]
mod tests {
    use crate::{ByteSpaceId, OffsetRange};

    use super::*;

    #[test]
    fn represents_many_to_many_and_irreversible_coordinate_changes() {
        let transport = ByteSpaceId::new(1).expect("transport space");
        let plaintext = ByteSpaceId::new(2).expect("plaintext space");
        let inputs = vec![extent(transport, 0, 16), extent(transport, 32, 16)];
        let outputs = vec![extent(plaintext, 0, 24)];
        let many = MappingSpan::new(MappingRelation::ManyToMany, inputs.clone(), outputs.clone())
            .expect("many-to-many mapping");
        let irreversible = MappingSpan::new(MappingRelation::Irreversible, inputs, outputs)
            .expect("irreversible mapping");

        assert!(!many.supports_exact_reverse_lookup());
        assert!(!irreversible.supports_exact_reverse_lookup());
    }

    #[test]
    fn exact_mapping_rejects_false_offset_equivalence() {
        let source = ByteSpaceId::new(1).expect("source space");
        let output = ByteSpaceId::new(2).expect("output space");
        assert_eq!(
            MappingSpan::new(
                MappingRelation::Exact,
                vec![extent(source, 0, 16)],
                vec![extent(output, 0, 15)],
            ),
            Err(MappingError::ExactLengthMismatch)
        );
    }

    fn extent(space: ByteSpaceId, start: u64, len: u64) -> ByteExtentRef {
        ByteExtentRef {
            space,
            range: OffsetRange::new(start, len).expect("valid test range"),
        }
    }
}
