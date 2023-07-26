//! Domain transaction sortition related logic.

use codec::Encode;
use domain_runtime_primitives::DomainCoreApi;
use sp_api::ProvideRuntimeApi;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use subspace_core_primitives::crypto::blake2b_256_hash;
use subspace_core_primitives::{bidirectional_distance, U256};

/// Transaction sortition for inclusion in a proposed bundle.
pub(crate) struct TransactionSelector<Block, Client> {
    /// VRF signature hash from the proof of election.
    pub bundle_vrf_hash: U256,

    /// Current tx range.
    pub tx_range: U256,

    /// Runtime API.
    pub client: Arc<Client>,

    _p: std::marker::PhantomData<Block>,
}

impl<Block, Client> TransactionSelector<Block, Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: DomainCoreApi<Block>,
{
    pub(crate) fn new(bundle_vrf_hash: U256, tx_range: U256, client: Arc<Client>) -> Self {
        Self {
            bundle_vrf_hash,
            tx_range,
            client,
            _p: Default::default(),
        }
    }

    /// Checks if the transaction should be selected based on the
    /// sortition scheme
    pub(crate) fn is_within_tx_range(
        &self,
        at: Block::Hash,
        tx: Block::Extrinsic,
    ) -> Result<bool, TransactionSelectError> {
        let maybe_signer_id_hash = self
            .client
            .runtime_api()
            .extract_signer(at, vec![tx])?
            .into_iter()
            .next()
            .and_then(|(maybe_signer, _)| {
                maybe_signer.map(|signer| {
                    let bytes = signer.encode();
                    U256::from_be_bytes(blake2b_256_hash(&bytes))
                })
            });

        if let Some(signer_id_hash) = maybe_signer_id_hash {
            // Check if the signer Id hash is within the tx range
            Ok(signer_in_tx_range(
                &self.bundle_vrf_hash,
                &signer_id_hash,
                &self.tx_range,
            ))
        } else {
            // Unsigned transactions are always in the range.
            Ok(true)
        }
    }
}

/// Error type for transaction selection.
#[derive(Debug, thiserror::Error)]
pub enum TransactionSelectError {
    #[error(transparent)]
    RuntimeApi(#[from] sp_api::ApiError),

    #[error(transparent)]
    Blockchain(#[from] sp_blockchain::Error),
}

/// Checks if the signer Id hash is within the tx range
fn signer_in_tx_range(bundle_vrf_hash: &U256, signer_id_hash: &U256, tx_range: &U256) -> bool {
    let distance_from_vrf_hash = bidirectional_distance(bundle_vrf_hash, signer_id_hash);
    distance_from_vrf_hash <= (*tx_range / 2)
}

#[cfg(test)]
mod tests {
    use super::signer_in_tx_range;
    use num_traits::ops::wrapping::{WrappingAdd, WrappingSub};
    use subspace_core_primitives::U256;

    #[test]
    fn test_tx_range() {
        let tx_range = U256::MAX / 4;
        let bundle_vrf_hash = U256::MAX / 2;

        let signer_id_hash = bundle_vrf_hash + U256::from(10_u64);
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash - U256::from(10_u64);
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash + U256::MAX / 8;
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash - U256::MAX / 8;
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash + U256::MAX / 8 + U256::from(1_u64);
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash - U256::MAX / 8 - U256::from(1_u64);
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash + U256::MAX / 4;
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash - U256::MAX / 4;
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));
    }

    #[test]
    fn test_tx_range_wrap_under_flow() {
        let tx_range = U256::MAX / 4;
        let bundle_vrf_hash = U256::from(100_u64);

        let signer_id_hash = bundle_vrf_hash + U256::from(1000_u64);
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash.wrapping_sub(&U256::from(1000_u64));
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash + U256::MAX / 8;
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let v = U256::MAX / 8;
        let signer_id_hash = bundle_vrf_hash.wrapping_sub(&v);
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash + U256::MAX / 8 + U256::from(1_u64);
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let v = U256::MAX / 8 + U256::from(1_u64);
        let signer_id_hash = bundle_vrf_hash.wrapping_sub(&v);
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash + U256::MAX / 4;
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let v = U256::MAX / 4;
        let signer_id_hash = bundle_vrf_hash.wrapping_sub(&v);
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));
    }

    #[test]
    fn test_tx_range_wrap_over_flow() {
        let tx_range = U256::MAX / 4;
        let v = U256::MAX;
        let bundle_vrf_hash = v.wrapping_sub(&U256::from(100_u64));

        let signer_id_hash = bundle_vrf_hash.wrapping_add(&U256::from(1000_u64));
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash - U256::from(1000_u64);
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let v = U256::MAX / 8;
        let signer_id_hash = bundle_vrf_hash.wrapping_add(&v);
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash - U256::MAX / 8;
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let v = U256::MAX / 8 + U256::from(1_u64);
        let signer_id_hash = bundle_vrf_hash.wrapping_add(&v);
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash - U256::MAX / 8 - U256::from(1_u64);
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let v = U256::MAX / 4;
        let signer_id_hash = bundle_vrf_hash.wrapping_add(&v);
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));

        let signer_id_hash = bundle_vrf_hash - U256::MAX / 4;
        assert!(!signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));
    }

    #[test]
    fn test_tx_range_max() {
        let tx_range = U256::MAX;
        let bundle_vrf_hash = U256::MAX / 2;

        let signer_id_hash = bundle_vrf_hash + U256::from(10_u64);
        assert!(signer_in_tx_range(
            &bundle_vrf_hash,
            &signer_id_hash,
            &tx_range
        ));
    }
}
