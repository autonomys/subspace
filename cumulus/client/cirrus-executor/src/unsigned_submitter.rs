use crate::LOG_TARGET;
use futures::FutureExt;
use sc_client_api::HeaderBackend;
use sp_api::ProvideRuntimeApi;
use sp_core::traits::SpawnNamed;
use sp_executor::{BundleEquivocationProof, ExecutorApi, FraudProof, InvalidTransactionProof};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{self, Permit, Sender};

const UNSIGNED_MESSAGE_BUFFER_SIZE: usize = 128;

#[derive(Debug, Clone)]
pub(crate) enum UnsignedMessage {
    Fraud(FraudProof),
    BundleEquivocation(BundleEquivocationProof),
    InvalidTransaction(InvalidTransactionProof),
}

/// Submits various executor-specific unsigned extrinsic to the primary node.
#[derive(Clone)]
pub(crate) struct UnsignedSubmitter {
    sender: Sender<UnsignedMessage>,
}

impl UnsignedSubmitter {
    pub(crate) fn new<Block, PBlock, PClient, Spawner>(
        primary_chain_client: Arc<PClient>,
        spawner: &Spawner,
    ) -> Self
    where
        Block: BlockT,
        PBlock: BlockT,
        PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
        PClient::Api: ExecutorApi<PBlock, Block::Hash>,
        Spawner: SpawnNamed + ?Sized,
    {
        let (sender, mut receiver) = mpsc::channel(UNSIGNED_MESSAGE_BUFFER_SIZE);

        spawner.spawn_blocking("cirrus-submit-unsigned-extrinsic", None, {
            async move {
                let runtime_api = primary_chain_client.runtime_api();

                while let Some(msg) = receiver.recv().await {
                    let at = BlockId::Hash(primary_chain_client.info().best_hash);
                    match msg {
                        UnsignedMessage::Fraud(fraud_proof) => {
                            if let Err(error) =
                                runtime_api.submit_fraud_proof_unsigned(&at, fraud_proof)
                            {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "Failed to submit fraud proof"
                                );
                            }
                        }
                        UnsignedMessage::BundleEquivocation(bundle_equivocation_proof) => {
                            if let Err(error) = runtime_api
                                .submit_bundle_equivocation_proof_unsigned(
                                    &at,
                                    bundle_equivocation_proof,
                                )
                            {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "Failed to submit bundle equivocation proof"
                                );
                            }
                        }
                        UnsignedMessage::InvalidTransaction(invalid_transaction_proof) => {
                            if let Err(error) = runtime_api
                                .submit_invalid_transaction_proof_unsigned(
                                    &at,
                                    invalid_transaction_proof,
                                )
                            {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "Failed to submit invalid transaction proof"
                                );
                            }
                        }
                    }
                }
            }
            .boxed()
        });

        Self { sender }
    }

    pub(crate) fn try_reserve(&self) -> Result<Permit<'_, UnsignedMessage>, TrySendError<()>> {
        self.sender.try_reserve()
    }
}
