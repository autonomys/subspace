use codec::Decode;
use sp_domains::{Bundle, ExecutorPublicKey, ExecutorSignature, ProofOfElection, SignedBundle};
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_runtime::RuntimeAppPublic;
use subspace_core_primitives::BlockNumber;

/// Trait for retrieving the necessary info for collecting the receipts in a new domain bundle.
pub(crate) trait ReceiptInterface<Hash> {
    fn head_receipt_number(&self, at: Hash) -> Result<BlockNumber, sp_api::ApiError>;
    fn maximum_receipt_drift(&self, at: Hash) -> Result<BlockNumber, sp_api::ApiError>;
}

type SignedOpaqueBundle<Block, PBlock> = sp_domains::SignedOpaqueBundle<
    NumberFor<PBlock>,
    <PBlock as BlockT>::Hash,
    <Block as BlockT>::Hash,
>;

pub(crate) fn sign_new_bundle<Block: BlockT, PBlock: BlockT>(
    bundle: Bundle<Block::Extrinsic, NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
    keystore: SyncCryptoStorePtr,
    proof_of_election: ProofOfElection<Block::Hash>,
) -> Result<SignedOpaqueBundle<Block, PBlock>, sp_blockchain::Error> {
    let to_sign = bundle.hash();
    match SyncCryptoStore::sign_with(
        &*keystore,
        ExecutorPublicKey::ID,
        &proof_of_election.executor_public_key.clone().into(),
        to_sign.as_ref(),
    ) {
        Ok(Some(signature)) => {
            let signed_bundle = SignedBundle {
                bundle,
                proof_of_election,
                signature: ExecutorSignature::decode(&mut signature.as_slice()).map_err(|err| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Failed to decode the signature of bundle: {err}"
                    )))
                })?,
            };

            // TODO: Re-enable the bundle gossip over X-Net when the compact bundle is supported.
            // if let Err(e) = self.bundle_sender.unbounded_send(signed_bundle.clone()) {
            // tracing::error!(target: LOG_TARGET, error = ?e, "Failed to send transaction bundle");
            // }

            Ok(signed_bundle.into_signed_opaque_bundle())
        }
        Ok(None) => Err(sp_blockchain::Error::Application(Box::from(
            "This should not happen as the existence of key was just checked",
        ))),
        Err(error) => Err(sp_blockchain::Error::Application(Box::from(format!(
            "Error occurred when signing the bundle: {error}"
        )))),
    }
}
