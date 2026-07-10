use std::fmt;

use crate::OffsetRange;

use super::{
    ExtentManifestRef, ExtentPage, ExtentPageError, ExtentPageRef, RangeState, SealedExtentPage,
};

pub trait ExtentPageSource {
    type Error;

    fn load(&mut self, reference: &ExtentPageRef) -> Result<Option<ExtentPage>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentPageReferenceMismatch {
    pub expected: ExtentPageRef,
    pub actual: ExtentPageRef,
}

#[derive(Debug)]
pub enum ExtentReadError<SourceError> {
    Source(SourceError),
    PageMissing(ExtentPageRef),
    InvalidPage(ExtentPageError),
    PageReferenceMismatch(Box<ExtentPageReferenceMismatch>),
}

impl<SourceError: fmt::Display> fmt::Display for ExtentReadError<SourceError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(formatter, "extent page source failed: {error}"),
            Self::PageMissing(reference) => {
                write!(formatter, "extent page {} is missing", reference.digest)
            }
            Self::InvalidPage(error) => write!(formatter, "stored extent page is invalid: {error}"),
            Self::PageReferenceMismatch(mismatch) => write!(
                formatter,
                "extent page reference mismatch: expected {}, loaded {}",
                mismatch.expected.digest, mismatch.actual.digest
            ),
        }
    }
}

impl<SourceError: fmt::Debug + fmt::Display> std::error::Error for ExtentReadError<SourceError> {}

enum Pending {
    Page(ExtentPageRef),
    State(RangeState),
}

pub struct ExtentRangeReader<Source> {
    source: Source,
    query: OffsetRange,
    pending: Vec<Pending>,
    failed: bool,
}

impl<Source> ExtentRangeReader<Source> {
    pub fn new(manifest: ExtentManifestRef, query: OffsetRange, source: Source) -> Self {
        let pending = manifest
            .root()
            .filter(|root| root.covered.overlaps(query))
            .map_or_else(Vec::new, |root| vec![Pending::Page(root)]);
        Self {
            source,
            query,
            pending,
            failed: false,
        }
    }

    pub fn into_source(self) -> Source {
        self.source
    }
}

impl<Source: ExtentPageSource> Iterator for ExtentRangeReader<Source> {
    type Item = Result<RangeState, ExtentReadError<Source::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }

        while let Some(pending) = self.pending.pop() {
            match pending {
                Pending::State(state) => return Some(Ok(state)),
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

impl<Source: ExtentPageSource> ExtentRangeReader<Source> {
    fn expand_page(
        &mut self,
        expected: ExtentPageRef,
    ) -> Result<(), ExtentReadError<Source::Error>> {
        let page = self
            .source
            .load(&expected)
            .map_err(ExtentReadError::Source)?
            .ok_or(ExtentReadError::PageMissing(expected))?;
        let sealed = SealedExtentPage::from_page(expected.space, page)
            .map_err(ExtentReadError::InvalidPage)?;
        if sealed.reference() != expected {
            return Err(ExtentReadError::PageReferenceMismatch(Box::new(
                ExtentPageReferenceMismatch {
                    expected,
                    actual: sealed.reference(),
                },
            )));
        }

        match sealed.into_page() {
            ExtentPage::Leaf(entries) => {
                self.pending.extend(
                    entries
                        .into_vec()
                        .into_iter()
                        .rev()
                        .filter(|state| state.extent().range.overlaps(self.query))
                        .map(Pending::State),
                );
            }
            ExtentPage::Branch(children) => {
                self.pending.extend(
                    children
                        .into_vec()
                        .into_iter()
                        .rev()
                        .filter(|child| child.covered.overlaps(self.query))
                        .map(Pending::Page),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, convert::Infallible};

    use crate::{
        ByteExtentRef, ByteRangeRef, ByteSpaceId, ContentDigest, ExtentPageSink,
        PagedExtentBuilder, SegmentId,
    };

    use super::*;

    #[derive(Default)]
    struct MemoryPageStore {
        pages: BTreeMap<ContentDigest, ExtentPage>,
        loads: usize,
    }

    impl ExtentPageSink for MemoryPageStore {
        type Error = Infallible;

        fn persist(&mut self, page: SealedExtentPage) -> Result<(), Self::Error> {
            self.pages.insert(page.reference().digest, page.into_page());
            Ok(())
        }
    }

    impl ExtentPageSource for MemoryPageStore {
        type Error = Infallible;

        fn load(&mut self, reference: &ExtentPageRef) -> Result<Option<ExtentPage>, Self::Error> {
            self.loads += 1;
            Ok(self.pages.get(&reference.digest).cloned())
        }
    }

    fn build_store() -> (MemoryPageStore, ExtentManifestRef) {
        let space = ByteSpaceId::new(1).expect("space ID");
        let segment = SegmentId::new(1).expect("segment ID");
        let mut builder = PagedExtentBuilder::new(space, MemoryPageStore::default());
        for offset in 0..20_000_u64 {
            let range = OffsetRange::new(offset, 1).expect("range");
            builder
                .append(
                    RangeState::present(
                        ByteExtentRef { space, range },
                        ByteRangeRef {
                            segment,
                            range,
                            digest: ContentDigest::for_bytes(&offset.to_be_bytes()),
                        },
                    )
                    .expect("matching stored range"),
                )
                .expect("ordered extent");
        }
        builder.finish().expect("extent tree")
    }

    #[test]
    fn reads_a_narrow_range_without_loading_the_whole_tree() {
        let (store, manifest) = build_store();
        let query = OffsetRange::new(10_000, 10).expect("query");
        let mut reader = ExtentRangeReader::new(manifest, query, store);
        let states = reader
            .by_ref()
            .collect::<Result<Vec<_>, _>>()
            .expect("valid pages");
        let store = reader.into_source();

        assert_eq!(states.len(), 10);
        assert_eq!(states[0].extent().range.start(), 10_000);
        assert_eq!(states[9].extent().range.start(), 10_009);
        assert_eq!(store.loads, 3);
    }

    #[test]
    fn rejects_a_page_that_does_not_match_its_content_address() {
        let (mut store, manifest) = build_store();
        let root = manifest.root().expect("root page");
        let ExtentPage::Branch(children) = store.pages.get_mut(&root.digest).expect("stored root")
        else {
            panic!("large fixture must have a branch root");
        };
        *children = children[..children.len() - 1].to_vec().into_boxed_slice();

        let query = OffsetRange::new(10_000, 1).expect("query");
        let mut reader = ExtentRangeReader::new(manifest, query, store);
        assert!(matches!(
            reader.next(),
            Some(Err(ExtentReadError::PageReferenceMismatch(_)))
        ));
        assert!(reader.next().is_none());
    }

    #[test]
    fn rejects_branch_children_from_another_byte_space() {
        let (mut store, manifest) = build_store();
        let root = manifest.root().expect("root page");
        let ExtentPage::Branch(children) = store.pages.get_mut(&root.digest).expect("stored root")
        else {
            panic!("large fixture must have a branch root");
        };
        children[0].space = ByteSpaceId::new(2).expect("other space ID");

        let query = OffsetRange::new(0, 1).expect("query");
        let mut reader = ExtentRangeReader::new(manifest, query, store);
        assert!(matches!(
            reader.next(),
            Some(Err(ExtentReadError::InvalidPage(
                ExtentPageError::MixedByteSpaces
            )))
        ));
        assert!(reader.next().is_none());
    }
}
