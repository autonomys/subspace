use async_trait::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{CALL_EXECUTION_FAILED_CODE, ErrorCode, ErrorObjectOwned};
use std::thread;
use subspace_test_service::MockConsensusNode;
use tokio::runtime::Builder as TokioBuilder;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

pub enum ConsensusCommand {
    ProduceBlock {
        wait_for_bundle: bool,
        respond_to: oneshot::Sender<Result<(), String>>,
    },
    ProduceBlocks {
        count: u64,
        wait_for_bundle: bool,
        respond_to: oneshot::Sender<Result<(), String>>,
    },
    Shutdown {
        respond_to: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub struct ConsensusControl {
    sender: mpsc::UnboundedSender<ConsensusCommand>,
}

impl ConsensusControl {
    fn new(sender: mpsc::UnboundedSender<ConsensusCommand>) -> Self {
        Self { sender }
    }

    async fn send_command<T>(
        &self,
        make_command: impl FnOnce(oneshot::Sender<T>) -> ConsensusCommand,
    ) -> Result<T, String> {
        let (respond_to, respond_from) = oneshot::channel();
        self.sender
            .send(make_command(respond_to))
            .map_err(|_| "Consensus task terminated".to_string())?;
        respond_from
            .await
            .map_err(|_| "Consensus task terminated".to_string())
    }

    pub async fn produce_block(&self, wait_for_bundle: bool) -> Result<(), String> {
        self.send_command(|respond_to| ConsensusCommand::ProduceBlock {
            wait_for_bundle,
            respond_to,
        })
        .await
        .and_then(|r| r)
    }

    pub async fn produce_blocks(&self, count: u64, wait_for_bundle: bool) -> Result<(), String> {
        self.send_command(|respond_to| ConsensusCommand::ProduceBlocks {
            count,
            wait_for_bundle,
            respond_to,
        })
        .await
        .and_then(|r| r)
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        self.send_command(|respond_to| ConsensusCommand::Shutdown { respond_to })
            .await
    }
}

pub type ConsensusCommandReceiver = mpsc::UnboundedReceiver<ConsensusCommand>;

pub fn consensus_control_channel() -> (ConsensusControl, ConsensusCommandReceiver) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (ConsensusControl::new(sender), receiver)
}

#[rpc(server)]
pub trait FarmerlessDevRpc {
    /// Produce a single consensus block.
    #[method(name = "dev_produceBlock")]
    async fn produce_block(&self, wait_for_bundle: Option<bool>) -> RpcResult<()>;

    /// Produce `count` consensus blocks.
    #[method(name = "dev_produceBlocks")]
    async fn produce_blocks(&self, count: u64, wait_for_bundle: Option<bool>) -> RpcResult<()>;
}

#[derive(Clone)]
struct FarmerlessDevRpcImpl {
    consensus: ConsensusControl,
}

fn to_rpc_error(err: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::ServerError(CALL_EXECUTION_FAILED_CODE).code(),
        err.to_string(),
        None::<()>,
    )
}

#[async_trait]
impl FarmerlessDevRpcServer for FarmerlessDevRpcImpl {
    async fn produce_block(&self, wait_for_bundle: Option<bool>) -> RpcResult<()> {
        let wait_for_bundle = wait_for_bundle.unwrap_or(false);
        self.consensus
            .produce_block(wait_for_bundle)
            .await
            .map_err(to_rpc_error)
    }

    async fn produce_blocks(&self, count: u64, wait_for_bundle: Option<bool>) -> RpcResult<()> {
        if count == 0 {
            return Ok(());
        }

        let wait_for_bundle = wait_for_bundle.unwrap_or(false);
        self.consensus
            .produce_blocks(count, wait_for_bundle)
            .await
            .map_err(to_rpc_error)
    }
}

pub fn manual_block_production_rpc(consensus: ConsensusControl) -> jsonrpsee::RpcModule<()> {
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .merge(FarmerlessDevRpcImpl { consensus }.into_rpc())
        .expect("manual block RPC merge must succeed");
    module
}

async fn produce_single_block(
    consensus: &mut MockConsensusNode,
    wait_for_bundle: bool,
) -> Result<(), String> {
    if wait_for_bundle {
        let (slot, _) = consensus
            .produce_slot_and_wait_for_bundle_submission()
            .await;
        consensus
            .produce_block_with_slot(slot)
            .await
            .map_err(|err| err.to_string())
    } else {
        let slot = consensus.produce_slot();
        consensus
            .produce_block_with_slot(slot)
            .await
            .map_err(|err| err.to_string())
    }
}

async fn produce_multiple_blocks(
    consensus: &mut MockConsensusNode,
    count: u64,
    wait_for_bundle: bool,
) -> Result<(), String> {
    if wait_for_bundle {
        for _ in 0..count {
            produce_single_block(consensus, true).await?;
        }
        Ok(())
    } else {
        consensus
            .produce_blocks(count)
            .await
            .map_err(|err| err.to_string())
    }
}

async fn run_consensus_command_loop(
    mut consensus: MockConsensusNode,
    mut commands: ConsensusCommandReceiver,
) {
    while let Some(command) = commands.recv().await {
        match command {
            ConsensusCommand::ProduceBlock {
                wait_for_bundle,
                respond_to,
            } => {
                let result = produce_single_block(&mut consensus, wait_for_bundle).await;
                if respond_to.send(result).is_err() {
                    warn!("Caller dropped receiver for ProduceBlock command");
                }
            }
            ConsensusCommand::ProduceBlocks {
                count,
                wait_for_bundle,
                respond_to,
            } => {
                let result = produce_multiple_blocks(&mut consensus, count, wait_for_bundle).await;
                if respond_to.send(result).is_err() {
                    warn!("Caller dropped receiver for ProduceBlocks command");
                }
            }
            ConsensusCommand::Shutdown { respond_to } => {
                if respond_to.send(()).is_err() {
                    warn!("Caller dropped receiver for Shutdown command");
                }
                break;
            }
        }
    }
}

pub fn spawn_consensus_worker(
    consensus: MockConsensusNode,
    commands: ConsensusCommandReceiver,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("consensus-control".into())
        .spawn(move || {
            let rt = TokioBuilder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create control runtime");
            rt.block_on(run_consensus_command_loop(consensus, commands));
        })
        .expect("Failed to spawn consensus control thread")
}
