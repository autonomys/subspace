use crate::fraud_proof::FraudProofError;
use sp_domains::ExecutorPublicKey;

/// Error type for domain gossip handling.
#[derive(Debug, thiserror::Error)]
pub enum GossipMessageError {
    #[error("Bundle equivocation error")]
    BundleEquivocation,
    #[error(transparent)]
    FraudProof(#[from] FraudProofError),
    #[error(transparent)]
    Client(Box<sp_blockchain::Error>),
    #[error(transparent)]
    RuntimeApi(#[from] sp_api::ApiError),
    #[error(transparent)]
    RecvError(#[from] crossbeam::channel::RecvError),
    #[error("Failed to send local receipt result because the channel is disconnected")]
    SendError,
    #[error("The signature of bundle is invalid")]
    BadBundleSignature,
    #[error("Invalid bundle author, got: {got}, expected: {expected}")]
    InvalidBundleAuthor {
        got: ExecutorPublicKey,
        expected: ExecutorPublicKey,
    },
}

impl From<sp_blockchain::Error> for GossipMessageError {
    fn from(error: sp_blockchain::Error) -> Self {
        Self::Client(Box::new(error))
    }
}
