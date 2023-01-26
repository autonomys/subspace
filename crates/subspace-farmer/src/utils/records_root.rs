use std::error::Error;
use subspace_core_primitives::{RecordsRoot, SegmentIndex};

#[derive(Debug, Clone)]
pub struct SegmentIndexKey(Vec<u8>);

impl From<SegmentIndex> for SegmentIndexKey {
    fn from(value: SegmentIndex) -> Self {
        Self(value.to_be_bytes().to_vec())
    }
}

impl TryFrom<SegmentIndexKey> for SegmentIndex {
    type Error = Box<dyn Error>;

    fn try_from(value: SegmentIndexKey) -> Result<Self, Self::Error> {
        let data: [u8; 8] = value.0[..8].try_into()?;

        Ok(u64::from_be_bytes(data))
    }
}

impl From<Vec<u8>> for SegmentIndexKey {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for SegmentIndexKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct RecordsRootValue(Vec<u8>);

impl From<RecordsRoot> for RecordsRootValue {
    fn from(value: RecordsRoot) -> Self {
        Self(value.to_bytes().to_vec())
    }
}

impl TryFrom<Vec<u8>> for RecordsRootValue {
    type Error = Box<dyn Error>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(RecordsRootValue(value))
    }
}
