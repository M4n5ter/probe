mod builder;
mod model;
mod page;
mod reader;

pub use builder::{MappingBuildError, MappingPageSink, PagedMappingBuilder};
pub use model::{
    ExtentSetRef, IntegrityIssueSetRef, MAPPING_SPAN_MAX_ARITY, MappingError, MappingRelation,
    MappingSide, MappingSpan, TransformEdge, TransformIntegrity, TransformKind, TransformMapping,
    TransformMappingError, TransformRevision,
};
pub use page::{
    MAPPING_PAGE_FANOUT, MappingManifestRef, MappingPage, MappingPageError, MappingPageRef,
    MappingPageSummary, SealedMappingPage,
};
pub use reader::{
    MappedExtentReader, MappingPageReferenceMismatch, MappingPageSource, MappingReadError,
    MappingReader,
};
