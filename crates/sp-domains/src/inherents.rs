//! Inherents for domain

use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "std")]
use sp_inherents::{Error, InherentData};
use sp_inherents::{InherentIdentifier, IsFatalError};

/// The domain inherent identifier.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"domains_";

/// Errors that can occur while checking provided inherent data.
#[derive(Debug, Encode)]
#[cfg_attr(feature = "std", derive(Decode))]
pub enum InherentError {
    /// Incorrect parent state root.
    IncorrectParentStateRoot,
}

impl IsFatalError for InherentError {
    fn is_fatal_error(&self) -> bool {
        true
    }
}

/// The type of the Domains inherent data.
#[derive(Debug, Encode, Decode)]
pub struct InherentType<Hash> {
    /// Parent state root.
    pub parent_state_root: Hash,
}

/// Provides the parent state root for Domains inherent data
#[cfg(feature = "std")]
pub struct InherentDataProvider<Hash> {
    data: InherentType<Hash>,
}

#[cfg(feature = "std")]
impl<Hash> InherentDataProvider<Hash> {
    /// Create new inherent data provider from the given `data`.
    pub fn new(parent_state_root: Hash) -> Self {
        Self {
            data: InherentType { parent_state_root },
        }
    }

    /// Returns the `data` of this inherent data provider.
    pub fn data(&self) -> &InherentType<Hash> {
        &self.data
    }
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl<Hash> sp_inherents::InherentDataProvider for InherentDataProvider<Hash>
where
    Hash: Send + Sync + Encode + Decode,
{
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
