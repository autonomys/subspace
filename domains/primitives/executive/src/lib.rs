//! Inherents for Executive pallet
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "std")]
use sp_inherents::{Error, InherentData};
use sp_inherents::{InherentIdentifier, IsFatalError};

/// Executive inherent identifier.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"executve";

#[derive(Debug, Encode)]
#[cfg_attr(feature = "std", derive(Decode))]
pub enum InherentError {
    MissingRuntimeCode,
    IncorrectRuntimeCode,
}

impl IsFatalError for InherentError {
    fn is_fatal_error(&self) -> bool {
        true
    }
}

/// The type of the Subspace inherent data.
#[derive(Debug, Encode, Decode)]
pub struct InherentType {
    /// Upgraded runtime code.
    pub maybe_code: Option<Vec<u8>>,
}

/// Provides the set code inherent data.
#[cfg(feature = "std")]
pub struct InherentDataProvider {
    data: InherentType,
}

#[cfg(feature = "std")]
impl InherentDataProvider {
    /// Create new inherent data provider from the given `data`.
    pub fn new(maybe_code: Option<Vec<u8>>) -> Self {
        Self {
            data: InherentType { maybe_code },
        }
    }

    /// Returns the `data` of this inherent data provider.
    pub fn data(&self) -> &InherentType {
        &self.data
    }
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
    async fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {
        inherent_data.put_data(INHERENT_IDENTIFIER, &self.data)
    }

    async fn try_handle_error(
        &self,
        identifier: &InherentIdentifier,
        error: &[u8],
    ) -> Option<Result<(), Error>> {
        if *identifier != INHERENT_IDENTIFIER {
            return None;
        }

        let error = InherentError::decode(&mut &*error).ok()?;

        Some(Err(Error::Application(Box::from(format!("{error:?}")))))
    }
}
