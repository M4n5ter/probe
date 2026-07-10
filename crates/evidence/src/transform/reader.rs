use std::fmt;

use crate::ByteExtentRef;

use super::{
    model::{ExtentSetRef, MappingSide, MappingSpan, TransformMapping, TransformMappingError},
    page::{MappingManifestRef, MappingPage, MappingPageError, MappingPageRef, SealedMappingPage},
};

pub trait MappingPageSource {
    type Error;

    fn load(&mut self, reference: &MappingPageRef) -> Result<Option<MappingPage>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPageReferenceMismatch {
    pub expected: MappingPageRef,
    pub actual: MappingPageRef,
}

#[derive(Debug)]
pub enum MappingReadError<SourceError> {
    Source(SourceError),
    PageMissing(MappingPageRef),
    InvalidPage(MappingPageError),
    PageReferenceMismatch(Box<MappingPageReferenceMismatch>),
}

impl<SourceError: fmt::Display> fmt::Display for MappingReadError<SourceError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(formatter, "mapping page source failed: {error}"),
            Self::PageMissing(reference) => {
                write!(formatter, "mapping page {} is missing", reference.digest())
            }
            Self::InvalidPage(error) => {
                write!(formatter, "stored mapping page is invalid: {error}")
            }
            Self::PageReferenceMismatch(mismatch) => write!(
                formatter,
                "mapping page reference mismatch: expected {}, loaded {}",
                mismatch.expected.digest(),
                mismatch.actual.digest()
            ),
        }
    }
}

impl<SourceError: fmt::Debug + fmt::Display> std::error::Error for MappingReadError<SourceError> {}

enum Pending {
    Page(MappingPageRef),
    Span(MappingSpan),
}

pub struct MappingReader<Source> {
    source: Source,
    pending: Vec<Pending>,
    failed: bool,
}

impl<Source> MappingReader<Source> {
    pub fn new(manifest: MappingManifestRef, source: Source) -> Self {
        Self {
            source,
            pending: vec![Pending::Page(manifest.root())],
            failed: false,
        }
    }

    pub fn into_source(self) -> Source {
        self.source
    }
}

impl<Source: MappingPageSource> Iterator for MappingReader<Source> {
    type Item = Result<MappingSpan, MappingReadError<Source::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }

        while let Some(pending) = self.pending.pop() {
            match pending {
                Pending::Span(span) => return Some(Ok(span)),
                Pending::Page(reference) => {
                    if let Err(error) = self.expand_page(reference) {
                        self.failed = true;
                        self.pending.clear();
                        return Some(Err(error));
                    }
                }
            }
        }
        None
    }
}

impl<Source: MappingPageSource> MappingReader<Source> {
    fn expand_page(
        &mut self,
        expected: MappingPageRef,
    ) -> Result<(), MappingReadError<Source::Error>> {
        let page = self
            .source
            .load(&expected)
            .map_err(MappingReadError::Source)?
            .ok_or(MappingReadError::PageMissing(expected))?;
        let sealed = SealedMappingPage::from_page(page).map_err(MappingReadError::InvalidPage)?;
        if sealed.reference() != expected {
            return Err(MappingReadError::PageReferenceMismatch(Box::new(
                MappingPageReferenceMismatch {
                    expected,
                    actual: sealed.reference(),
                },
            )));
        }

        match sealed.into_page() {
            MappingPage::Leaf(spans) => self
                .pending
                .extend(spans.into_vec().into_iter().rev().map(Pending::Span)),
            MappingPage::Branch(children) => self
                .pending
                .extend(children.into_vec().into_iter().rev().map(Pending::Page)),
        }
        Ok(())
    }
}

pub struct MappedExtentReader<Source> {
    mappings: MappingReader<Source>,
    side: MappingSide,
    current: std::vec::IntoIter<ByteExtentRef>,
}

impl<Source> MappedExtentReader<Source> {
    pub fn new(
        mapping: TransformMapping,
        extents: ExtentSetRef,
        source: Source,
    ) -> Result<Self, TransformMappingError> {
        let expected = match extents.side() {
            MappingSide::Inputs => mapping.inputs(),
            MappingSide::Outputs => mapping.outputs(),
        };
        if extents != expected {
            return Err(TransformMappingError::ExtentSetMismatch(extents.side()));
        }
        Ok(Self {
            mappings: MappingReader::new(mapping.manifest(), source),
            side: extents.side(),
            current: Vec::new().into_iter(),
        })
    }

    pub fn into_source(self) -> Source {
        self.mappings.into_source()
    }
}

impl<Source: MappingPageSource> Iterator for MappedExtentReader<Source> {
    type Item = Result<ByteExtentRef, MappingReadError<Source::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(extent) = self.current.next() {
                return Some(Ok(extent));
            }
            let span = match self.mappings.next()? {
                Ok(span) => span,
                Err(error) => return Some(Err(error)),
            };
            self.current = span.into_extents(self.side).into_vec().into_iter();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use crate::{ByteExtentRef, ByteSpaceId, MappingPageSink, OffsetRange, PagedMappingBuilder};

    use super::*;
    use crate::{ContentDigest, MappingRelation};

    #[derive(Default)]
    struct MemoryPageStore {
        pages: BTreeMap<ContentDigest, MappingPage>,
        loads: Arc<AtomicUsize>,
    }

    impl MappingPageSink for MemoryPageStore {
        type Error = Infallible;

        fn persist(&mut self, page: SealedMappingPage) -> Result<(), Self::Error> {
            self.pages
                .insert(page.reference().digest(), page.into_page());
            Ok(())
        }
    }

    impl MappingPageSource for MemoryPageStore {
        type Error = Infallible;

        fn load(&mut self, reference: &MappingPageRef) -> Result<Option<MappingPage>, Self::Error> {
            self.loads.fetch_add(1, Ordering::Relaxed);
            Ok(self.pages.get(&reference.digest()).cloned())
        }
    }

    #[test]
    fn traverses_mapping_pages_lazily_and_exposes_extent_sets() {
        let (store, mapping) = build_store(20_000);
        let loads = Arc::clone(&store.loads);
        let mut reader = MappingReader::new(mapping.manifest(), store);
        assert_eq!(loads.load(Ordering::Relaxed), 0);

        let first = reader.next().expect("first mapping").expect("valid pages");
        assert_eq!(first.inputs()[0].range.start(), 0);
        assert_eq!(loads.load(Ordering::Relaxed), 3);
        assert_eq!(reader.count(), 19_999);

        let (store, mapping) = build_store(20_000);
        let mut inputs =
            MappedExtentReader::new(mapping, mapping.inputs(), store).expect("bound input set");
        assert_eq!(
            inputs
                .next()
                .expect("first input")
                .expect("valid input")
                .space,
            ByteSpaceId::new(1).expect("input space")
        );
    }

    #[test]
    fn rejects_a_mapping_page_that_does_not_match_its_content_address() {
        let (mut store, mapping) = build_store(20_000);
        let root = mapping.manifest().root();
        let MappingPage::Branch(children) =
            store.pages.get_mut(&root.digest()).expect("stored root")
        else {
            panic!("large fixture must have a branch root");
        };
        *children = children[..children.len() - 1].to_vec().into_boxed_slice();

        let mut reader = MappingReader::new(mapping.manifest(), store);
        assert!(matches!(
            reader.next(),
            Some(Err(MappingReadError::PageReferenceMismatch(_)))
        ));
        assert!(reader.next().is_none());
    }

    #[test]
    fn extent_sets_cannot_be_attached_to_an_unrelated_mapping() {
        let (_, first) = build_store_from(0, 2);
        let (_, second) = build_store_from(10_000, 2);
        assert_eq!(
            first.inputs().extent_count(),
            second.inputs().extent_count()
        );
        assert!(matches!(
            TransformMapping::from_parts(first.manifest(), second.inputs(), first.outputs()),
            Err(TransformMappingError::ExtentSetMismatch(
                MappingSide::Inputs
            ))
        ));
    }

    fn build_store(mappings: u64) -> (MemoryPageStore, TransformMapping) {
        build_store_from(0, mappings)
    }

    fn build_store_from(start: u64, mappings: u64) -> (MemoryPageStore, TransformMapping) {
        let mut builder = PagedMappingBuilder::new(MemoryPageStore::default());
        for offset in start..start + mappings {
            builder.append(exact_span(offset)).expect("mapping append");
        }
        builder.finish().expect("mapping tree")
    }

    fn exact_span(offset: u64) -> MappingSpan {
        let input = ByteSpaceId::new(1).expect("input space");
        let output = ByteSpaceId::new(2).expect("output space");
        MappingSpan::new(
            MappingRelation::Exact,
            vec![extent(input, offset)],
            vec![extent(output, offset)],
        )
        .expect("exact mapping")
    }

    fn extent(space: ByteSpaceId, offset: u64) -> ByteExtentRef {
        ByteExtentRef {
            space,
            range: OffsetRange::new(offset, 1).expect("range"),
        }
    }
}
