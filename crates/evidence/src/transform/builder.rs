use std::fmt;

use super::{
    model::{MappingSpan, TransformMapping},
    page::{
        MAPPING_PAGE_FANOUT, MappingManifestRef, MappingPageError, MappingPageRef,
        SealedMappingPage,
    },
};

pub trait MappingPageSink {
    type Error;

    fn persist(&mut self, page: SealedMappingPage) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum MappingBuildError<SinkError> {
    Page(MappingPageError),
    Sink(SinkError),
    Poisoned,
    Empty,
}

impl<SinkError: fmt::Display> fmt::Display for MappingBuildError<SinkError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Page(error) => write!(formatter, "invalid mapping page: {error}"),
            Self::Sink(error) => write!(formatter, "mapping page sink failed: {error}"),
            Self::Poisoned => formatter.write_str("mapping builder is poisoned"),
            Self::Empty => formatter.write_str("transform mapping must not be empty"),
        }
    }
}

impl<SinkError: fmt::Debug + fmt::Display> std::error::Error for MappingBuildError<SinkError> {}

pub struct PagedMappingBuilder<Sink> {
    sink: Sink,
    leaf: Vec<MappingSpan>,
    levels: Vec<Vec<MappingPageRef>>,
    poisoned: bool,
}

impl<Sink: MappingPageSink> PagedMappingBuilder<Sink> {
    pub fn new(sink: Sink) -> Self {
        Self {
            sink,
            leaf: Vec::with_capacity(MAPPING_PAGE_FANOUT),
            levels: Vec::new(),
            poisoned: false,
        }
    }

    pub fn append(&mut self, span: MappingSpan) -> Result<(), MappingBuildError<Sink::Error>> {
        self.ensure_usable()?;
        span.validate()
            .map_err(MappingPageError::InvalidMapping)
            .map_err(MappingBuildError::Page)?;
        self.leaf.push(span);
        if self.leaf.len() == MAPPING_PAGE_FANOUT {
            self.flush_leaf()?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(Sink, TransformMapping), MappingBuildError<Sink::Error>> {
        self.ensure_usable()?;
        self.flush_leaf()?;
        let root = self.finish_root()?.ok_or(MappingBuildError::Empty)?;
        let manifest = MappingManifestRef::new(root);
        Ok((self.sink, TransformMapping::for_manifest(manifest)))
    }

    fn ensure_usable(&self) -> Result<(), MappingBuildError<Sink::Error>> {
        if self.poisoned {
            Err(MappingBuildError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn flush_leaf(&mut self) -> Result<(), MappingBuildError<Sink::Error>> {
        self.ensure_usable()?;
        if self.leaf.is_empty() {
            return Ok(());
        }
        let spans = std::mem::take(&mut self.leaf);
        self.leaf = Vec::with_capacity(MAPPING_PAGE_FANOUT);
        let page = match SealedMappingPage::leaf(spans) {
            Ok(page) => page,
            Err(error) => {
                self.poisoned = true;
                return Err(MappingBuildError::Page(error));
            }
        };
        self.persist_and_push(page)
    }

    fn persist_and_push(
        &mut self,
        page: SealedMappingPage,
    ) -> Result<(), MappingBuildError<Sink::Error>> {
        let reference = page.reference();
        if let Err(error) = self.sink.persist(page) {
            self.poisoned = true;
            return Err(MappingBuildError::Sink(error));
        }
        if let Err(error) = self.push_reference(reference) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn push_reference(
        &mut self,
        reference: MappingPageRef,
    ) -> Result<(), MappingBuildError<Sink::Error>> {
        let level = usize::from(reference.level());
        if self.levels.len() <= level {
            self.levels.resize_with(level + 1, Vec::new);
        }
        self.levels[level].push(reference);
        if self.levels[level].len() == MAPPING_PAGE_FANOUT {
            let children = std::mem::take(&mut self.levels[level]);
            let parent = SealedMappingPage::branch(children).map_err(MappingBuildError::Page)?;
            self.persist_and_push(parent)?;
        }
        Ok(())
    }

    fn finish_root(&mut self) -> Result<Option<MappingPageRef>, MappingBuildError<Sink::Error>> {
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
            let parent = match SealedMappingPage::branch(children) {
                Ok(parent) => parent,
                Err(error) => {
                    self.poisoned = true;
                    return Err(MappingBuildError::Page(error));
                }
            };
            self.persist_and_push(parent)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use crate::{ByteExtentRef, ByteSpaceId, OffsetRange};

    use super::*;

    #[derive(Default)]
    struct MemorySink {
        pages: Vec<SealedMappingPage>,
    }

    impl MappingPageSink for MemorySink {
        type Error = Infallible;

        fn persist(&mut self, page: SealedMappingPage) -> Result<(), Self::Error> {
            self.pages.push(page);
            Ok(())
        }
    }

    struct FailingSink;

    impl MappingPageSink for FailingSink {
        type Error = &'static str;

        fn persist(&mut self, _page: SealedMappingPage) -> Result<(), Self::Error> {
            Err("injected persistence failure")
        }
    }

    #[test]
    fn builds_a_content_addressed_mapping_tree() {
        let mut builder = PagedMappingBuilder::new(MemorySink::default());
        for offset in 0..20_000_u64 {
            builder.append(exact_span(offset)).expect("mapping append");
        }
        let (sink, mapping) = builder.finish().expect("mapping tree");

        assert!(mapping.manifest().root().level() >= 2);
        assert_eq!(mapping.manifest().summary().mapping_count().get(), 20_000);
        assert!(sink.pages.iter().all(|page| match page.page() {
            super::super::page::MappingPage::Leaf(spans) => {
                spans.len() <= MAPPING_PAGE_FANOUT
            }
            super::super::page::MappingPage::Branch(children) => {
                children.len() <= MAPPING_PAGE_FANOUT
            }
        }));
    }

    #[test]
    fn sink_failure_permanently_poisoned_the_builder() {
        let mut builder = PagedMappingBuilder::new(FailingSink);
        for offset in 0..127_u64 {
            builder
                .append(exact_span(offset))
                .expect("buffered mapping");
        }
        assert!(matches!(
            builder.append(exact_span(127)),
            Err(MappingBuildError::Sink("injected persistence failure"))
        ));
        assert!(matches!(
            builder.append(exact_span(128)),
            Err(MappingBuildError::Poisoned)
        ));
        assert!(matches!(builder.finish(), Err(MappingBuildError::Poisoned)));
    }

    fn exact_span(offset: u64) -> MappingSpan {
        let input = ByteSpaceId::new(1).expect("input space");
        let output = ByteSpaceId::new(2).expect("output space");
        MappingSpan::new(
            super::super::model::MappingRelation::Exact,
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
