use std::fmt;

use crate::{ByteSpaceId, ContentDigest, OffsetRange};

use super::model::{GapReason, RangeState, RangeStateError, SourceScope};

pub const EXTENT_PAGE_FANOUT: usize = 128;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExtentSummary {
    pub extent_count: u64,
    pub present_bytes: u64,
    pub missing_bytes: u64,
    pub conflicting_bytes: u64,
}

impl ExtentSummary {
    pub fn add_state(&mut self, state: &RangeState) -> Result<(), ExtentPageError> {
        self.extent_count = self
            .extent_count
            .checked_add(1)
            .ok_or(ExtentPageError::SummaryOverflow)?;
        let bytes = state.extent().range.length().get();
        let target = match state {
            RangeState::Present { .. } => &mut self.present_bytes,
            RangeState::Missing { .. } => &mut self.missing_bytes,
            RangeState::Conflicting { .. } => &mut self.conflicting_bytes,
        };
        *target = target
            .checked_add(bytes)
            .ok_or(ExtentPageError::SummaryOverflow)?;
        Ok(())
    }

    pub fn merge(&mut self, other: Self) -> Result<(), ExtentPageError> {
        self.extent_count = self
            .extent_count
            .checked_add(other.extent_count)
            .ok_or(ExtentPageError::SummaryOverflow)?;
        self.present_bytes = self
            .present_bytes
            .checked_add(other.present_bytes)
            .ok_or(ExtentPageError::SummaryOverflow)?;
        self.missing_bytes = self
            .missing_bytes
            .checked_add(other.missing_bytes)
            .ok_or(ExtentPageError::SummaryOverflow)?;
        self.conflicting_bytes = self
            .conflicting_bytes
            .checked_add(other.conflicting_bytes)
            .ok_or(ExtentPageError::SummaryOverflow)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentPageRef {
    pub digest: ContentDigest,
    pub level: u8,
    pub space: ByteSpaceId,
    pub covered: OffsetRange,
    pub summary: ExtentSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtentPage {
    Leaf(Box<[RangeState]>),
    Branch(Box<[ExtentPageRef]>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedExtentPage {
    reference: ExtentPageRef,
    page: ExtentPage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentManifestRef {
    digest: ContentDigest,
    space: ByteSpaceId,
    root: Option<ExtentPageRef>,
    summary: ExtentSummary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentPageError {
    EmptyPage,
    PageFanoutExceeded,
    MixedByteSpaces,
    OverlappingOrUnordered,
    MixedChildLevels,
    LevelOverflow,
    CoveredRangeOverflow,
    SummaryOverflow,
    InvalidRangeState(RangeStateError),
    ManifestRootSpaceMismatch,
    ManifestSummaryMismatch,
    EmptyManifestSummary,
    ManifestDigestMismatch,
}

impl fmt::Display for ExtentPageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPage => "extent page must not be empty",
            Self::PageFanoutExceeded => "extent page exceeds its fixed fanout",
            Self::MixedByteSpaces => "extent page mixes byte spaces",
            Self::OverlappingOrUnordered => "extent page ranges overlap or are unordered",
            Self::MixedChildLevels => "branch page mixes child levels",
            Self::LevelOverflow => "extent page tree exceeds its level limit",
            Self::CoveredRangeOverflow => "extent page covered range overflows",
            Self::SummaryOverflow => "extent page summary overflows",
            Self::InvalidRangeState(error) => {
                return write!(formatter, "invalid range state: {error}");
            }
            Self::ManifestRootSpaceMismatch => {
                "extent manifest root belongs to a different byte space"
            }
            Self::ManifestSummaryMismatch => {
                "extent manifest summary differs from its root summary"
            }
            Self::EmptyManifestSummary => "an empty extent manifest must have a zero summary",
            Self::ManifestDigestMismatch => {
                "extent manifest digest does not match its canonical content"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ExtentPageError {}

impl ExtentManifestRef {
    pub fn new(space: ByteSpaceId, root: Option<ExtentPageRef>) -> Result<Self, ExtentPageError> {
        let summary = match root {
            Some(root) => root.summary,
            None => ExtentSummary::default(),
        };
        let summary = validate_manifest(space, root, summary)?;
        let digest = digest_manifest(space, root, summary);
        Ok(Self {
            digest,
            space,
            root,
            summary,
        })
    }

    pub fn empty(space: ByteSpaceId) -> Self {
        let summary = ExtentSummary::default();
        Self {
            digest: digest_manifest(space, None, summary),
            space,
            root: None,
            summary,
        }
    }

    pub fn decode(
        digest: ContentDigest,
        space: ByteSpaceId,
        root: Option<ExtentPageRef>,
        summary: ExtentSummary,
    ) -> Result<Self, ExtentPageError> {
        let summary = validate_manifest(space, root, summary)?;
        if digest != digest_manifest(space, root, summary) {
            return Err(ExtentPageError::ManifestDigestMismatch);
        }
        Ok(Self {
            digest,
            space,
            root,
            summary,
        })
    }

    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    pub const fn space(&self) -> ByteSpaceId {
        self.space
    }

    pub const fn root(&self) -> Option<ExtentPageRef> {
        self.root
    }

    pub const fn summary(&self) -> ExtentSummary {
        self.summary
    }
}

impl SealedExtentPage {
    pub const fn reference(&self) -> ExtentPageRef {
        self.reference
    }

    pub const fn page(&self) -> &ExtentPage {
        &self.page
    }

    pub fn into_page(self) -> ExtentPage {
        self.page
    }

    pub fn from_page(space: ByteSpaceId, page: ExtentPage) -> Result<Self, ExtentPageError> {
        let sealed = match page {
            ExtentPage::Leaf(entries) => Self::leaf(space, entries.into_vec())?,
            ExtentPage::Branch(children) => Self::branch(children.into_vec())?,
        };
        if sealed.reference.space != space {
            return Err(ExtentPageError::MixedByteSpaces);
        }
        Ok(sealed)
    }

    pub fn leaf(space: ByteSpaceId, entries: Vec<RangeState>) -> Result<Self, ExtentPageError> {
        require_page_size(entries.len())?;
        validate_states(space, &entries)?;
        let summary = summarize_states(&entries)?;
        let covered = covered_range(
            entries[0].extent().range.start(),
            entries[entries.len() - 1].extent().range.end(),
        )?;
        let page = ExtentPage::Leaf(entries.into_boxed_slice());
        let reference = ExtentPageRef {
            digest: digest_page(space, 0, &page),
            level: 0,
            space,
            covered,
            summary,
        };
        Ok(Self { reference, page })
    }

    pub fn branch(children: Vec<ExtentPageRef>) -> Result<Self, ExtentPageError> {
        require_page_size(children.len())?;
        validate_children(&children)?;
        let first = children[0];
        let last = children[children.len() - 1];
        let level = first
            .level
            .checked_add(1)
            .ok_or(ExtentPageError::LevelOverflow)?;
        let mut summary = ExtentSummary::default();
        for child in &children {
            summary.merge(child.summary)?;
        }
        let covered = covered_range(first.covered.start(), last.covered.end())?;
        let space = first.space;
        let page = ExtentPage::Branch(children.into_boxed_slice());
        let reference = ExtentPageRef {
            digest: digest_page(space, level, &page),
            level,
            space,
            covered,
            summary,
        };
        Ok(Self { reference, page })
    }
}

fn require_page_size(entries: usize) -> Result<(), ExtentPageError> {
    if entries == 0 {
        return Err(ExtentPageError::EmptyPage);
    }
    if entries > EXTENT_PAGE_FANOUT {
        return Err(ExtentPageError::PageFanoutExceeded);
    }
    Ok(())
}

fn validate_states(space: ByteSpaceId, entries: &[RangeState]) -> Result<(), ExtentPageError> {
    let mut previous_end = None;
    for state in entries {
        state
            .validate()
            .map_err(ExtentPageError::InvalidRangeState)?;
        let extent = state.extent();
        if extent.space != space {
            return Err(ExtentPageError::MixedByteSpaces);
        }
        if previous_end.is_some_and(|end| extent.range.start() < end) {
            return Err(ExtentPageError::OverlappingOrUnordered);
        }
        previous_end = Some(extent.range.end());
    }
    Ok(())
}

fn validate_manifest(
    space: ByteSpaceId,
    root: Option<ExtentPageRef>,
    summary: ExtentSummary,
) -> Result<ExtentSummary, ExtentPageError> {
    let Some(root) = root else {
        if summary != ExtentSummary::default() {
            return Err(ExtentPageError::EmptyManifestSummary);
        }
        return Ok(summary);
    };
    if root.space != space {
        return Err(ExtentPageError::ManifestRootSpaceMismatch);
    }
    if root.summary != summary {
        return Err(ExtentPageError::ManifestSummaryMismatch);
    }
    Ok(summary)
}

fn validate_children(children: &[ExtentPageRef]) -> Result<(), ExtentPageError> {
    let first = children[0];
    let mut previous_end = None;
    for child in children {
        if child.space != first.space {
            return Err(ExtentPageError::MixedByteSpaces);
        }
        if child.level != first.level {
            return Err(ExtentPageError::MixedChildLevels);
        }
        if previous_end.is_some_and(|end| child.covered.start() < end) {
            return Err(ExtentPageError::OverlappingOrUnordered);
        }
        previous_end = Some(child.covered.end());
    }
    Ok(())
}

fn summarize_states(entries: &[RangeState]) -> Result<ExtentSummary, ExtentPageError> {
    let mut summary = ExtentSummary::default();
    for state in entries {
        summary.add_state(state)?;
    }
    Ok(summary)
}

fn covered_range(start: u64, end: u64) -> Result<OffsetRange, ExtentPageError> {
    OffsetRange::new(start, end - start).map_err(|_| ExtentPageError::CoveredRangeOverflow)
}

fn digest_page(space: ByteSpaceId, level: u8, page: &ExtentPage) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"probe-evidence-extent-page\0");
    hasher.update(&space.get().to_be_bytes());
    hasher.update(&[level]);
    match page {
        ExtentPage::Leaf(entries) => {
            hasher.update(b"leaf\0");
            hasher.update(&(entries.len() as u64).to_be_bytes());
            for entry in entries {
                hash_state(&mut hasher, entry);
            }
        }
        ExtentPage::Branch(children) => {
            hasher.update(b"branch\0");
            hasher.update(&(children.len() as u64).to_be_bytes());
            for child in children {
                hasher.update(child.digest.as_bytes());
                hasher.update(&child.covered.start().to_be_bytes());
                hasher.update(&child.covered.length().get().to_be_bytes());
                hash_summary(&mut hasher, child.summary);
            }
        }
    }
    ContentDigest::new(*hasher.finalize().as_bytes())
}

fn digest_manifest(
    space: ByteSpaceId,
    root: Option<ExtentPageRef>,
    summary: ExtentSummary,
) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"probe-evidence-extent-manifest\0");
    hasher.update(&space.get().to_be_bytes());
    match root {
        Some(root) => {
            hasher.update(&[1]);
            hasher.update(root.digest.as_bytes());
            hasher.update(&[root.level]);
            hasher.update(&root.space.get().to_be_bytes());
            hasher.update(&root.covered.start().to_be_bytes());
            hasher.update(&root.covered.length().get().to_be_bytes());
            hash_summary(&mut hasher, root.summary);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hash_summary(&mut hasher, summary);
    ContentDigest::new(*hasher.finalize().as_bytes())
}

fn hash_state(hasher: &mut blake3::Hasher, state: &RangeState) {
    let extent = state.extent();
    hasher.update(&extent.range.start().to_be_bytes());
    hasher.update(&extent.range.length().get().to_be_bytes());
    match state {
        RangeState::Present { storage, .. } => {
            hasher.update(&[0]);
            hasher.update(&storage.segment.get().to_be_bytes());
            hasher.update(&storage.range.start().to_be_bytes());
            hasher.update(&storage.range.length().get().to_be_bytes());
            hasher.update(storage.digest.as_bytes());
        }
        RangeState::Missing { gap, .. } => {
            hasher.update(&[1, gap_reason_tag(gap.reason)]);
            hash_scope(hasher, gap.source_scope);
            hasher.update(
                &gap.observed_loss
                    .map_or(0, |identifier| identifier.get())
                    .to_be_bytes(),
            );
        }
        RangeState::Conflicting { alternatives, .. } => {
            hasher.update(&[2]);
            hasher.update(alternatives.root.as_bytes());
            hasher.update(&alternatives.alternatives.to_be_bytes());
        }
    }
}

fn hash_summary(hasher: &mut blake3::Hasher, summary: ExtentSummary) {
    hasher.update(&summary.extent_count.to_be_bytes());
    hasher.update(&summary.present_bytes.to_be_bytes());
    hasher.update(&summary.missing_bytes.to_be_bytes());
    hasher.update(&summary.conflicting_bytes.to_be_bytes());
}

const fn gap_reason_tag(reason: GapReason) -> u8 {
    match reason {
        GapReason::KernelRingOverrun => 0,
        GapReason::UserspaceQueueFull => 1,
        GapReason::PacketSnaplen => 2,
        GapReason::TcpSequenceMissing => 3,
        GapReason::DecryptUnavailable => 4,
        GapReason::DecryptAuthenticationFailed => 5,
        GapReason::SourceAttachedLate => 6,
        GapReason::RetentionEvicted => 7,
        GapReason::ExplicitRedaction => 8,
    }
}

fn hash_scope(hasher: &mut blake3::Hasher, scope: SourceScope) {
    match scope {
        SourceScope::CapturePoint(identifier) => {
            hasher.update(&[0]);
            hasher.update(&identifier.get().to_be_bytes());
        }
        SourceScope::PlaintextStream(identifier) => {
            hasher.update(&[1]);
            hasher.update(&identifier.get().to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ByteExtentRef, ByteRangeRef, SegmentId};

    use super::*;

    fn present_state(space: ByteSpaceId, extent_length: u64, storage_length: u64) -> RangeState {
        RangeState::Present {
            extent: ByteExtentRef {
                space,
                range: OffsetRange::new(0, extent_length).expect("extent range"),
            },
            storage: ByteRangeRef {
                segment: SegmentId::new(1).expect("segment ID"),
                range: OffsetRange::new(0, storage_length).expect("storage range"),
                digest: ContentDigest::for_bytes(b"payload"),
            },
        }
    }

    #[test]
    fn sealing_and_decoding_reject_semantically_invalid_range_states() {
        let space = ByteSpaceId::new(1).expect("space ID");
        let malformed = present_state(space, 8, 7);

        assert!(matches!(
            SealedExtentPage::leaf(space, vec![malformed.clone()]),
            Err(ExtentPageError::InvalidRangeState(
                RangeStateError::LengthMismatch
            ))
        ));
        assert!(matches!(
            SealedExtentPage::from_page(
                space,
                ExtentPage::Leaf(vec![malformed].into_boxed_slice())
            ),
            Err(ExtentPageError::InvalidRangeState(
                RangeStateError::LengthMismatch
            ))
        ));
    }

    #[test]
    fn manifest_decode_validates_content_address_and_bound_fields() {
        let space = ByteSpaceId::new(1).expect("space ID");
        let other_space = ByteSpaceId::new(2).expect("other space ID");
        let page =
            SealedExtentPage::leaf(space, vec![present_state(space, 8, 8)]).expect("valid page");
        let manifest = ExtentManifestRef::new(space, Some(page.reference())).expect("manifest");

        assert_eq!(
            ExtentManifestRef::decode(
                manifest.digest(),
                manifest.space(),
                manifest.root(),
                manifest.summary(),
            ),
            Ok(manifest)
        );
        assert_eq!(
            ExtentManifestRef::decode(
                ContentDigest::for_bytes(b"wrong manifest"),
                manifest.space(),
                manifest.root(),
                manifest.summary(),
            ),
            Err(ExtentPageError::ManifestDigestMismatch)
        );
        assert_eq!(
            ExtentManifestRef::new(other_space, manifest.root()),
            Err(ExtentPageError::ManifestRootSpaceMismatch)
        );
        let mismatched_summary = ExtentSummary {
            present_bytes: manifest.summary().present_bytes + 1,
            ..manifest.summary()
        };
        assert_eq!(
            ExtentManifestRef::decode(
                manifest.digest(),
                manifest.space(),
                manifest.root(),
                mismatched_summary,
            ),
            Err(ExtentPageError::ManifestSummaryMismatch)
        );
    }

    #[test]
    fn empty_manifest_requires_a_zero_summary() {
        let space = ByteSpaceId::new(1).expect("space ID");
        let manifest = ExtentManifestRef::empty(space);
        let nonzero = ExtentSummary {
            extent_count: 1,
            ..ExtentSummary::default()
        };

        assert_eq!(manifest.root(), None);
        assert_eq!(manifest.summary(), ExtentSummary::default());
        assert_eq!(
            ExtentManifestRef::decode(manifest.digest(), space, None, nonzero),
            Err(ExtentPageError::EmptyManifestSummary)
        );
    }
}
