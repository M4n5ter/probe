use crate::{ByteSpaceId, ByteViewId, ExtentManifestRef, ExtentSummary};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteView {
    id: ByteViewId,
    extents: ExtentManifestRef,
}

impl ByteView {
    pub const fn new(id: ByteViewId, extents: ExtentManifestRef) -> Self {
        Self { id, extents }
    }

    pub const fn id(&self) -> ByteViewId {
        self.id
    }

    pub const fn space(&self) -> ByteSpaceId {
        self.extents.space()
    }

    pub const fn extents(&self) -> ExtentManifestRef {
        self.extents
    }

    pub const fn summary(&self) -> ExtentSummary {
        self.extents.summary()
    }
}

#[cfg(test)]
mod tests {
    use crate::ByteSpaceId;

    use super::*;

    #[test]
    fn derives_space_and_summary_from_the_validated_manifest() {
        let id = ByteViewId::new(1).expect("view ID");
        let space = ByteSpaceId::new(2).expect("space ID");
        let manifest = ExtentManifestRef::empty(space);
        let view = ByteView::new(id, manifest);

        assert_eq!(view.id(), id);
        assert_eq!(view.space(), space);
        assert_eq!(view.extents(), manifest);
        assert_eq!(view.summary(), ExtentSummary::default());
    }
}
