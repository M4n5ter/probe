use std::{fmt, num::NonZeroU64};

use crate::{ByteExtentRef, ContentDigest};

use super::model::{MappingError, MappingSpan, mapping_relation_tag};

pub const MAPPING_PAGE_FANOUT: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPageSummary {
    mapping_count: NonZeroU64,
    input_extent_count: NonZeroU64,
    output_extent_count: NonZeroU64,
}

impl MappingPageSummary {
    pub fn from_counts(
        mapping_count: u64,
        input_extent_count: u64,
        output_extent_count: u64,
    ) -> Result<Self, MappingPageError> {
        Ok(Self {
            mapping_count: NonZeroU64::new(mapping_count).ok_or(MappingPageError::EmptyPage)?,
            input_extent_count: NonZeroU64::new(input_extent_count)
                .ok_or(MappingPageError::EmptyMappingSide)?,
            output_extent_count: NonZeroU64::new(output_extent_count)
                .ok_or(MappingPageError::EmptyMappingSide)?,
        })
    }

    pub const fn mapping_count(self) -> NonZeroU64 {
        self.mapping_count
    }

    pub const fn input_extent_count(self) -> NonZeroU64 {
        self.input_extent_count
    }

    pub const fn output_extent_count(self) -> NonZeroU64 {
        self.output_extent_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPageRef {
    digest: ContentDigest,
    level: u8,
    summary: MappingPageSummary,
}

impl MappingPageRef {
    pub const fn from_parts(digest: ContentDigest, level: u8, summary: MappingPageSummary) -> Self {
        Self {
            digest,
            level,
            summary,
        }
    }

    pub const fn digest(self) -> ContentDigest {
        self.digest
    }

    pub const fn level(self) -> u8 {
        self.level
    }

    pub const fn summary(self) -> MappingPageSummary {
        self.summary
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MappingPage {
    Leaf(Box<[MappingSpan]>),
    Branch(Box<[MappingPageRef]>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedMappingPage {
    reference: MappingPageRef,
    page: MappingPage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingManifestRef {
    digest: ContentDigest,
    root: MappingPageRef,
    summary: MappingPageSummary,
}

impl MappingManifestRef {
    pub fn new(root: MappingPageRef) -> Self {
        let summary = root.summary;
        Self {
            digest: digest_manifest(root, summary),
            root,
            summary,
        }
    }

    pub fn from_parts(
        digest: ContentDigest,
        root: MappingPageRef,
        summary: MappingPageSummary,
    ) -> Result<Self, MappingPageError> {
        if summary != root.summary {
            return Err(MappingPageError::ManifestSummaryMismatch);
        }
        let expected = digest_manifest(root, summary);
        if digest != expected {
            return Err(MappingPageError::ManifestDigestMismatch);
        }
        Ok(Self {
            digest,
            root,
            summary,
        })
    }

    pub const fn digest(self) -> ContentDigest {
        self.digest
    }

    pub const fn root(self) -> MappingPageRef {
        self.root
    }

    pub const fn summary(self) -> MappingPageSummary {
        self.summary
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPageError {
    EmptyPage,
    EmptyMappingSide,
    PageFanoutExceeded,
    InvalidMapping(MappingError),
    MixedChildLevels,
    LevelOverflow,
    SummaryOverflow,
    ManifestSummaryMismatch,
    ManifestDigestMismatch,
}

impl fmt::Display for MappingPageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPage => formatter.write_str("mapping page must not be empty"),
            Self::EmptyMappingSide => {
                formatter.write_str("mapping page cannot contain an empty mapping side")
            }
            Self::PageFanoutExceeded => {
                formatter.write_str("mapping page exceeds its fixed fanout")
            }
            Self::InvalidMapping(error) => write!(formatter, "invalid mapping span: {error}"),
            Self::MixedChildLevels => formatter.write_str("branch page mixes child levels"),
            Self::LevelOverflow => formatter.write_str("mapping page tree exceeds its level limit"),
            Self::SummaryOverflow => formatter.write_str("mapping page summary overflows"),
            Self::ManifestSummaryMismatch => {
                formatter.write_str("mapping manifest summary differs from its root")
            }
            Self::ManifestDigestMismatch => {
                formatter.write_str("mapping manifest digest does not match its contents")
            }
        }
    }
}

impl std::error::Error for MappingPageError {}

impl SealedMappingPage {
    pub const fn reference(&self) -> MappingPageRef {
        self.reference
    }

    pub const fn page(&self) -> &MappingPage {
        &self.page
    }

    pub fn into_page(self) -> MappingPage {
        self.page
    }

    pub fn from_page(page: MappingPage) -> Result<Self, MappingPageError> {
        match page {
            MappingPage::Leaf(spans) => Self::leaf(spans.into_vec()),
            MappingPage::Branch(children) => Self::branch(children.into_vec()),
        }
    }

    pub fn leaf(spans: Vec<MappingSpan>) -> Result<Self, MappingPageError> {
        require_page_size(spans.len())?;
        let summary = summarize_spans(&spans)?;
        let page = MappingPage::Leaf(spans.into_boxed_slice());
        let reference = MappingPageRef {
            digest: digest_page(0, &page),
            level: 0,
            summary,
        };
        Ok(Self { reference, page })
    }

    pub fn branch(children: Vec<MappingPageRef>) -> Result<Self, MappingPageError> {
        require_page_size(children.len())?;
        let first_level = children[0].level;
        if children.iter().any(|child| child.level != first_level) {
            return Err(MappingPageError::MixedChildLevels);
        }
        let level = first_level
            .checked_add(1)
            .ok_or(MappingPageError::LevelOverflow)?;
        let summary = summarize_children(&children)?;
        let page = MappingPage::Branch(children.into_boxed_slice());
        let reference = MappingPageRef {
            digest: digest_page(level, &page),
            level,
            summary,
        };
        Ok(Self { reference, page })
    }
}

fn require_page_size(entries: usize) -> Result<(), MappingPageError> {
    if entries == 0 {
        return Err(MappingPageError::EmptyPage);
    }
    if entries > MAPPING_PAGE_FANOUT {
        return Err(MappingPageError::PageFanoutExceeded);
    }
    Ok(())
}

fn summarize_spans(spans: &[MappingSpan]) -> Result<MappingPageSummary, MappingPageError> {
    let mut mappings = 0_u64;
    let mut inputs = 0_u64;
    let mut outputs = 0_u64;
    for span in spans {
        span.validate().map_err(MappingPageError::InvalidMapping)?;
        mappings = mappings
            .checked_add(1)
            .ok_or(MappingPageError::SummaryOverflow)?;
        inputs = inputs
            .checked_add(span.inputs().len() as u64)
            .ok_or(MappingPageError::SummaryOverflow)?;
        outputs = outputs
            .checked_add(span.outputs().len() as u64)
            .ok_or(MappingPageError::SummaryOverflow)?;
    }
    MappingPageSummary::from_counts(mappings, inputs, outputs)
}

fn summarize_children(children: &[MappingPageRef]) -> Result<MappingPageSummary, MappingPageError> {
    let mut mappings = 0_u64;
    let mut inputs = 0_u64;
    let mut outputs = 0_u64;
    for child in children {
        mappings = mappings
            .checked_add(child.summary.mapping_count.get())
            .ok_or(MappingPageError::SummaryOverflow)?;
        inputs = inputs
            .checked_add(child.summary.input_extent_count.get())
            .ok_or(MappingPageError::SummaryOverflow)?;
        outputs = outputs
            .checked_add(child.summary.output_extent_count.get())
            .ok_or(MappingPageError::SummaryOverflow)?;
    }
    MappingPageSummary::from_counts(mappings, inputs, outputs)
}

fn digest_page(level: u8, page: &MappingPage) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"probe-evidence-mapping-page\0");
    hasher.update(&[level]);
    match page {
        MappingPage::Leaf(spans) => {
            hasher.update(b"leaf\0");
            hasher.update(&(spans.len() as u64).to_be_bytes());
            for span in spans {
                hash_span(&mut hasher, span);
            }
        }
        MappingPage::Branch(children) => {
            hasher.update(b"branch\0");
            hasher.update(&(children.len() as u64).to_be_bytes());
            for child in children {
                hash_page_ref(&mut hasher, *child);
            }
        }
    }
    ContentDigest::new(*hasher.finalize().as_bytes())
}

fn digest_manifest(root: MappingPageRef, summary: MappingPageSummary) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"probe-evidence-mapping-manifest\0");
    hash_page_ref(&mut hasher, root);
    hash_summary(&mut hasher, summary);
    ContentDigest::new(*hasher.finalize().as_bytes())
}

fn hash_page_ref(hasher: &mut blake3::Hasher, reference: MappingPageRef) {
    hasher.update(reference.digest.as_bytes());
    hasher.update(&[reference.level]);
    hash_summary(hasher, reference.summary);
}

fn hash_summary(hasher: &mut blake3::Hasher, summary: MappingPageSummary) {
    hasher.update(&summary.mapping_count.get().to_be_bytes());
    hasher.update(&summary.input_extent_count.get().to_be_bytes());
    hasher.update(&summary.output_extent_count.get().to_be_bytes());
}

fn hash_span(hasher: &mut blake3::Hasher, span: &MappingSpan) {
    hasher.update(&[mapping_relation_tag(span.relation())]);
    hasher.update(&(span.inputs().len() as u64).to_be_bytes());
    for extent in span.inputs() {
        hash_extent(hasher, *extent);
    }
    hasher.update(&(span.outputs().len() as u64).to_be_bytes());
    for extent in span.outputs() {
        hash_extent(hasher, *extent);
    }
}

fn hash_extent(hasher: &mut blake3::Hasher, extent: ByteExtentRef) {
    hasher.update(&extent.space.get().to_be_bytes());
    hasher.update(&extent.range.start().to_be_bytes());
    hasher.update(&extent.range.length().get().to_be_bytes());
}
