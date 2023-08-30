//! Subspace block import implementation

use crate::Error;
use log::{debug, info, trace, warn};
use prometheus_endpoint::Registry;
use sc_client_api::backend::AuxStore;
use sc_consensus::block_import::{BlockImport, BlockImportParams};
use sc_consensus::import_queue::{
    BasicQueue, BoxJustificationImport, DefaultImportQueue, Verifier,
};
use sc_consensus_slots::check_equivocation;
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_DEBUG, CONSENSUS_TRACE};
use schnorrkel::context::SigningContext;
use sp_api::{ApiExt, BlockT, HeaderT, ProvideRuntimeApi, TransactionFor};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{HeaderBackend, Result as ClientResult};
use sp_consensus::{BlockOrigin, Error as ConsensusError};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::extract_subspace_digest_items;
use sp_consensus_subspace::{
    check_header, CheckedHeader, FarmerPublicKey, FarmerSignature, SubspaceApi, VerificationParams,
};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_proof_of_space::Table;
use subspace_solving::REWARD_SIGNING_CONTEXT;
use subspace_verification::VerifySolutionParams;

/// Start an import queue for the Subspace consensus algorithm.
///
/// This method returns the import queue, some data that needs to be passed to the block authoring
/// logic (`SubspaceLink`), and a future that must be run to
/// completion and is responsible for listening to finality notifications and
/// pruning the epoch changes tree.
///
/// The block import object provided must be the `SubspaceBlockImport` or a wrapper
/// of it, otherwise crucial import logic will be omitted.
// TODO: Create a struct for these parameters
#[allow(clippy::too_many_arguments)]
pub fn import_queue<PosTable, Block: BlockT, Client, SelectChain, Inner, SN>(
    block_import: Inner,
    justification_import: Option<BoxJustificationImport<Block>>,
    client: Arc<Client>,
    kzg: Kzg,
    select_chain: SelectChain,
    slot_now: SN,
    spawner: &impl sp_core::traits::SpawnEssentialNamed,
    registry: Option<&Registry>,
    telemetry: Option<TelemetryHandle>,
    is_authoring_blocks: bool,
) -> ClientResult<DefaultImportQueue<Block, Client>>
where
    PosTable: Table,
    Inner: BlockImport<Block, Error = ConsensusError, Transaction = TransactionFor<Client, Block>>
        + Send
        + Sync
        + 'static,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore + Send + Sync + 'static,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    SelectChain: sp_consensus::SelectChain<Block> + 'static,
    SN: Fn() -> Slot + Send + Sync + 'static,
{
    let verifier = SubspaceVerifier {
        client,
        kzg,
        select_chain,
        slot_now,
        telemetry,
        reward_signing_context: schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
        is_authoring_blocks,
        _pos_table: PhantomData::<PosTable>,
        _block: PhantomData,
    };

    Ok(BasicQueue::new(
        verifier,
        Box::new(block_import),
        justification_import,
        spawner,
        registry,
    ))
}

/// A verifier for Subspace blocks.
struct SubspaceVerifier<PosTable, Block: BlockT, Client, SelectChain, SN> {
    client: Arc<Client>,
    kzg: Kzg,
    select_chain: SelectChain,
    slot_now: SN,
    telemetry: Option<TelemetryHandle>,
    reward_signing_context: SigningContext,
    is_authoring_blocks: bool,
    _pos_table: PhantomData<PosTable>,
    _block: PhantomData<Block>,
}

impl<PosTable, Block, Client, SelectChain, SN>
    SubspaceVerifier<PosTable, Block, Client, SelectChain, SN>
where
    Block: BlockT,
    Client: AuxStore + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    SelectChain: sp_consensus::SelectChain<Block>,
{
    async fn check_and_report_equivocation(
        &self,
        slot_now: Slot,
        slot: Slot,
        header: &Block::Header,
        author: &FarmerPublicKey,
        origin: &BlockOrigin,
    ) -> Result<(), Error<Block::Header>> {
        // don't report any equivocations during initial sync
        // as they are most likely stale.
        if *origin == BlockOrigin::NetworkInitialSync {
            return Ok(());
        }

        // check if authorship of this header is an equivocation and return a proof if so.
        let equivocation_proof =
            match check_equivocation(&*self.client, slot_now, slot, header, author)
                .map_err(Error::Client)?
            {
                Some(proof) => proof,
                None => return Ok(()),
            };

        info!(
            "Slot author {:?} is equivocating at slot {} with headers {:?} and {:?}",
            author,
            slot,
            equivocation_proof.first_header.hash(),
            equivocation_proof.second_header.hash(),
        );

        if self.is_authoring_blocks {
            // get the best block on which we will build and send the equivocation report.
            let best_hash = self
                .select_chain
                .best_chain()
                .await
                .map(|h| h.hash())
                .map_err(|e| Error::Client(e.into()))?;

            // submit equivocation report at best block.
            self.client
                .runtime_api()
                .submit_report_equivocation_extrinsic(best_hash, equivocation_proof)
                .map_err(Error::RuntimeApi)?;

            info!(target: "subspace", "Submitted equivocation report for author {:?}", author);
        } else {
            info!(
                target: "subspace",
                "Not submitting equivocation report because node is not authoring blocks"
            );
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl<PosTable, Block, Client, SelectChain, SN> Verifier<Block>
    for SubspaceVerifier<PosTable, Block, Client, SelectChain, SN>
where
    PosTable: Table,
    Block: BlockT,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block> + Send + Sync + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    SelectChain: sp_consensus::SelectChain<Block>,
    SN: Fn() -> Slot + Send + Sync + 'static,
{
    async fn verify(
        &mut self,
        mut block: BlockImportParams<Block, ()>,
    ) -> Result<BlockImportParams<Block, ()>, String> {
        trace!(
            target: "subspace",
            "Verifying origin: {:?} header: {:?} justification(s): {:?} body: {:?}",
            block.origin,
            block.header,
            block.justifications,
            block.body,
        );

        let hash = block.header.hash();

        debug!(target: "subspace", "We have {:?} logs in this header", block.header.digest().logs().len());

        let subspace_digest_items = extract_subspace_digest_items::<
            Block::Header,
            FarmerPublicKey,
            FarmerPublicKey,
            FarmerSignature,
        >(&block.header)
        .map_err(Error::<Block::Header>::from)?;
        let pre_digest = subspace_digest_items.pre_digest;

        // Check if farmer's plot is burned.
        // TODO: Add to header and store in aux storage?
        if self
            .client
            .runtime_api()
            .is_in_block_list(
                *block.header.parent_hash(),
                &pre_digest.solution().public_key,
            )
            .or_else(|error| {
                if block.state_action.skip_execution_checks() {
                    Ok(false)
                } else {
                    Err(Error::<Block::Header>::RuntimeApi(error))
                }
            })?
        {
            warn!(
                target: "subspace",
                "Verifying block with solution provided by farmer in block list: {}",
                pre_digest.solution().public_key
            );

            return Err(Error::<Block::Header>::FarmerInBlockList(
                pre_digest.solution().public_key.clone(),
            )
            .into());
        }

        let slot_now = (self.slot_now)();

        // Stateless header verification only. This means only check that header contains required
        // contents, correct signature and valid Proof-of-Space, but because previous block is not
        // guaranteed to be imported at this point, it is not possible to verify
        // Proof-of-Archival-Storage. In order to verify PoAS randomness and solution range
        // from the header are checked against expected correct values during block import as well
        // as whether piece in the header corresponds to the actual archival history of the
        // blockchain.
        let checked_header = {
            // We add one to the current slot to allow for some small drift.
            // FIXME https://github.com/paritytech/substrate/issues/1019 in the future, alter this
            //  queue to allow deferring of headers
            check_header::<PosTable, _, FarmerPublicKey>(
                VerificationParams {
                    header: block.header.clone(),
                    slot_now: slot_now + 1,
                    verify_solution_params: &VerifySolutionParams {
                        #[cfg(not(feature = "pot"))]
                        global_randomness: subspace_digest_items.global_randomness,
                        #[cfg(feature = "pot")]
                        proof_of_time: pre_digest.pot_info().proof_of_time(),
                        solution_range: subspace_digest_items.solution_range,
                        piece_check_params: None,
                    },
                    reward_signing_context: &self.reward_signing_context,
                },
                Some(pre_digest),
                &self.kzg,
            )
            .map_err(Error::<Block::Header>::from)?
        };

        match checked_header {
            CheckedHeader::Checked(pre_header, verified_info) => {
                let slot = verified_info.pre_digest.slot();

                // the header is valid but let's check if there was something else already
                // proposed at the same slot by the given author. if there was, we will
                // report the equivocation to the runtime.
                if let Err(err) = self
                    .check_and_report_equivocation(
                        slot_now,
                        slot,
                        &block.header,
                        &verified_info.pre_digest.solution().public_key,
                        &block.origin,
                    )
                    .await
                {
                    warn!(
                        target: "subspace",
                        "Error checking/reporting Subspace equivocation: {}",
                        err
                    );
                }

                trace!(target: "subspace", "Checked {:?}; importing.", pre_header);
                telemetry!(
                    self.telemetry;
                    CONSENSUS_TRACE;
                    "subspace.checked_and_importing";
                    "pre_header" => ?pre_header,
                );

                block.header = pre_header;
                block.post_digests.push(verified_info.seal);
                block.post_hash = Some(hash);

                Ok(block)
            }
            CheckedHeader::Deferred(a, b) => {
                debug!(target: "subspace", "Checking {:?} failed; {:?}, {:?}.", hash, a, b);
                telemetry!(
                    self.telemetry;
                    CONSENSUS_DEBUG;
                    "subspace.header_too_far_in_future";
                    "hash" => ?hash, "a" => ?a, "b" => ?b
                );
                Err(Error::<Block::Header>::TooFarInFuture(hash).into())
            }
        }
    }
}
