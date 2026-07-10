use std::fmt;

use crate::ByteSpaceId;

use super::{
    model::RangeState,
    page::{
        EXTENT_PAGE_FANOUT, ExtentManifestRef, ExtentPageError, ExtentPageRef, ExtentSummary,
        SealedExtentPage,
    },
};

pub trait ExtentPageSink {
    type Error;

    fn persist(&mut self, page: SealedExtentPage) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum ExtentBuildError<SinkError> {
    Page(ExtentPageError),
    Sink(SinkError),
    Poisoned,
}

impl<SinkError: fmt::Display> fmt::Display for ExtentBuildError<SinkError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Page(error) => write!(formatter, "invalid extent page: {error}"),
            Self::Sink(error) => write!(formatter, "extent page sink failed: {error}"),
            Self::Poisoned => formatter.write_str("extent builder is permanently poisoned"),
        }
    }
}

impl<SinkError: fmt::Debug + fmt::Display> std::error::Error for ExtentBuildError<SinkError> {}

pub struct PagedExtentBuilder<Sink> {
    space: ByteSpaceId,
    sink: Sink,
    leaf: Vec<RangeState>,
    levels: Vec<Vec<ExtentPageRef>>,
    previous_end: Option<u64>,
    summary: ExtentSummary,
    poisoned: bool,
}

impl<Sink: ExtentPageSink> PagedExtentBuilder<Sink> {
    pub fn new(space: ByteSpaceId, sink: Sink) -> Self {
        Self {
            space,
            sink,
            leaf: Vec::with_capacity(EXTENT_PAGE_FANOUT),
            levels: Vec::new(),
            previous_end: None,
            summary: ExtentSummary::default(),
            poisoned: false,
        }
    }

    pub fn append(&mut self, state: RangeState) -> Result<(), ExtentBuildError<Sink::Error>> {
        self.require_healthy()?;
        state
            .validate()
            .map_err(ExtentPageError::InvalidRangeState)
            .map_err(ExtentBuildError::Page)?;
        let extent = state.extent();
        if extent.space != self.space {
            return Err(ExtentBuildError::Page(ExtentPageError::MixedByteSpaces));
        }
        if self
            .previous_end
            .is_some_and(|end| extent.range.start() < end)
        {
            return Err(ExtentBuildError::Page(
                ExtentPageError::OverlappingOrUnordered,
            ));
        }
        let mut summary = self.summary;
        summary.add_state(&state).map_err(ExtentBuildError::Page)?;
        let next_end = extent.range.end();
        self.leaf.push(state);
        if self.leaf.len() == EXTENT_PAGE_FANOUT {
            self.flush_leaf()?;
        }
        self.summary = summary;
        self.previous_end = Some(next_end);
        Ok(())
    }

    pub fn finish(mut self) -> Result<(Sink, ExtentManifestRef), ExtentBuildError<Sink::Error>> {
        self.require_healthy()?;
        self.flush_leaf()?;
        let root = self.finish_root()?;
        let manifest = ExtentManifestRef::new(self.space, root).map_err(ExtentBuildError::Page)?;
        if manifest.summary() != self.summary {
            return Err(ExtentBuildError::Page(
                ExtentPageError::ManifestSummaryMismatch,
            ));
        }
        Ok((self.sink, manifest))
    }

    fn require_healthy(&self) -> Result<(), ExtentBuildError<Sink::Error>> {
        if self.poisoned {
            return Err(ExtentBuildError::Poisoned);
        }
        Ok(())
    }

    fn flush_leaf(&mut self) -> Result<(), ExtentBuildError<Sink::Error>> {
        if self.leaf.is_empty() {
            return Ok(());
        }
        let entries = std::mem::take(&mut self.leaf);
        self.leaf = Vec::with_capacity(EXTENT_PAGE_FANOUT);
        let page = match SealedExtentPage::leaf(self.space, entries) {
            Ok(page) => page,
            Err(error) => {
                self.poisoned = true;
                return Err(ExtentBuildError::Page(error));
            }
        };
        self.persist_and_push(page)
    }

    fn persist_and_push(
        &mut self,
        page: SealedExtentPage,
    ) -> Result<(), ExtentBuildError<Sink::Error>> {
        let reference = page.reference();
        if let Err(error) = self.sink.persist(page) {
            self.poisoned = true;
            return Err(ExtentBuildError::Sink(error));
        }
        self.push_reference(reference)
    }

    fn push_reference(
        &mut self,
        reference: ExtentPageRef,
    ) -> Result<(), ExtentBuildError<Sink::Error>> {
        let level = usize::from(reference.level);
        if self.levels.len() <= level {
            self.levels.resize_with(level + 1, Vec::new);
        }
        self.levels[level].push(reference);
        if self.levels[level].len() == EXTENT_PAGE_FANOUT {
            let children = std::mem::take(&mut self.levels[level]);
            let parent = match SealedExtentPage::branch(children) {
                Ok(parent) => parent,
                Err(error) => {
                    self.poisoned = true;
                    return Err(ExtentBuildError::Page(error));
                }
            };
            self.persist_and_push(parent)?;
        }
        Ok(())
    }

    fn finish_root(&mut self) -> Result<Option<ExtentPageRef>, ExtentBuildError<Sink::Error>> {
        loop {
            let non_empty: Vec<_> = self
                .levels
                .iter()
                .enumerate()
                .filter(|(_, references)| !references.is_empty())
                .collect();
            let total = non_empty
                .iter()
                .map(|(_, references)| references.len())
                .sum::<usize>();
            if total == 0 {
                return Ok(None);
            }
            if total == 1 {
                let level = non_empty[0].0;
                return Ok(self.levels[level].pop());
            }
            let level = non_empty[0].0;
            let children = std::mem::take(&mut self.levels[level]);
            let parent = match SealedExtentPage::branch(children) {
                Ok(parent) => parent,
                Err(error) => {
                    self.poisoned = true;
                    return Err(ExtentBuildError::Page(error));
                }
            };
            self.persist_and_push(parent)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use crate::{
        ByteExtentRef, ByteRangeRef, ContentDigest, OffsetRange, SegmentId, id::ByteSpaceId,
    };

    use super::*;

    #[derive(Default)]
    struct MemorySink {
        pages: Vec<SealedExtentPage>,
    }

    impl ExtentPageSink for MemorySink {
        type Error = Infallible;

        fn persist(&mut self, page: SealedExtentPage) -> Result<(), Self::Error> {
            self.pages.push(page);
            Ok(())
        }
    }

    #[test]
    fn builds_a_bounded_page_tree_for_many_extents() {
        let space = ByteSpaceId::new(1).expect("space ID");
        let segment = SegmentId::new(1).expect("segment ID");
        let mut builder = PagedExtentBuilder::new(space, MemorySink::default());
        for offset in 0..20_000_u64 {
            let range = OffsetRange::new(offset, 1).expect("range");
            let state = RangeState::present(
                ByteExtentRef { space, range },
                ByteRangeRef {
                    segment,
                    range,
                    digest: ContentDigest::for_bytes(&offset.to_be_bytes()),
                },
            )
            .expect("matching stored range");
            builder.append(state).expect("ordered append");
        }
        let (sink, manifest) = builder.finish().expect("finish page tree");

        assert_eq!(manifest.summary().extent_count, 20_000);
        assert!(manifest.root().is_some_and(|root| root.level >= 2));
        assert!(sink.pages.iter().all(|page| match page.page() {
            super::super::page::ExtentPage::Leaf(entries) => {
                entries.len() <= EXTENT_PAGE_FANOUT
            }
            super::super::page::ExtentPage::Branch(children) => {
                children.len() <= EXTENT_PAGE_FANOUT
            }
        }));
    }

    #[test]
    fn rejects_cross_space_and_overlapping_extents() {
        let space = ByteSpaceId::new(1).expect("space ID");
        let other = ByteSpaceId::new(2).expect("other space ID");
        let capture = crate::CapturePointId::new(1).expect("capture point ID");
        let mut builder = PagedExtentBuilder::new(space, MemorySink::default());
        let gap = crate::LocatedGap {
            reason: crate::GapReason::TcpSequenceMissing,
            source_scope: crate::SourceScope::CapturePoint(capture),
            observed_loss: None,
        };
        builder
            .append(RangeState::missing(
                ByteExtentRef {
                    space,
                    range: OffsetRange::new(0, 8).expect("range"),
                },
                gap,
            ))
            .expect("first extent");
        assert!(
            builder
                .append(RangeState::missing(
                    ByteExtentRef {
                        space,
                        range: OffsetRange::new(7, 2).expect("range"),
                    },
                    gap,
                ))
                .is_err()
        );
        assert!(
            builder
                .append(RangeState::missing(
                    ByteExtentRef {
                        space: other,
                        range: OffsetRange::new(8, 2).expect("range"),
                    },
                    gap,
                ))
                .is_err()
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct InjectedFailure;

    impl fmt::Display for InjectedFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected persistence failure")
        }
    }

    struct FailingSink {
        fail_at: usize,
        persists: usize,
    }

    impl ExtentPageSink for FailingSink {
        type Error = InjectedFailure;

        fn persist(&mut self, _page: SealedExtentPage) -> Result<(), Self::Error> {
            self.persists += 1;
            if self.persists == self.fail_at {
                return Err(InjectedFailure);
            }
            Ok(())
        }
    }

    fn append_present<Sink: ExtentPageSink>(
        builder: &mut PagedExtentBuilder<Sink>,
        space: ByteSpaceId,
        offset: u64,
    ) -> Result<(), ExtentBuildError<Sink::Error>> {
        let range = OffsetRange::new(offset, 1).expect("range");
        builder.append(
            RangeState::present(
                ByteExtentRef { space, range },
                ByteRangeRef {
                    segment: SegmentId::new(1).expect("segment ID"),
                    range,
                    digest: ContentDigest::for_bytes(&offset.to_be_bytes()),
                },
            )
            .expect("valid present state"),
        )
    }

    #[test]
    fn leaf_persistence_failure_permanently_prevents_a_manifest() {
        let space = ByteSpaceId::new(1).expect("space ID");
        let mut builder = PagedExtentBuilder::new(
            space,
            FailingSink {
                fail_at: 1,
                persists: 0,
            },
        );
        for offset in 0..u64::try_from(EXTENT_PAGE_FANOUT - 1).expect("fanout fits u64") {
            append_present(&mut builder, space, offset).expect("buffered append");
        }

        assert!(matches!(
            append_present(
                &mut builder,
                space,
                u64::try_from(EXTENT_PAGE_FANOUT - 1).expect("fanout fits u64")
            ),
            Err(ExtentBuildError::Sink(InjectedFailure))
        ));
        assert!(matches!(
            append_present(&mut builder, space, 10_000),
            Err(ExtentBuildError::Poisoned)
        ));
        assert!(matches!(builder.finish(), Err(ExtentBuildError::Poisoned)));
    }

    #[test]
    fn parent_persistence_failure_permanently_prevents_a_manifest() {
        let space = ByteSpaceId::new(1).expect("space ID");
        let mut builder = PagedExtentBuilder::new(
            space,
            FailingSink {
                fail_at: EXTENT_PAGE_FANOUT + 1,
                persists: 0,
            },
        );
        let entry_count = EXTENT_PAGE_FANOUT * EXTENT_PAGE_FANOUT;

        for offset in 0..u64::try_from(entry_count - 1).expect("entry count fits u64") {
            append_present(&mut builder, space, offset).expect("durable leaf append");
        }
        assert!(matches!(
            append_present(
                &mut builder,
                space,
                u64::try_from(entry_count - 1).expect("entry count fits u64")
            ),
            Err(ExtentBuildError::Sink(InjectedFailure))
        ));
        assert!(matches!(builder.finish(), Err(ExtentBuildError::Poisoned)));
    }
}
