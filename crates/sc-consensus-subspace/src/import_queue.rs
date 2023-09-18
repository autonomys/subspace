//! Subspace block import implementation

#[cfg(feature = "pot")]
use crate::get_chain_constants;
use crate::Error;
#[cfg(feature = "pot")]
use futures::stream::FuturesUnordered;
#[cfg(feature = "pot")]
use futures::StreamExt;
use log::{debug, info, trace, warn};
use prometheus_endpoint::Registry;
use sc_client_api::backend::AuxStore;
use sc_consensus::block_import::{BlockImport, BlockImportParams};
use sc_consensus::import_queue::{
    BasicQueue, BoxJustificationImport, DefaultImportQueue, Verifier,
};
use sc_consensus_slots::check_equivocation;
#[cfg(feature = "pot")]
use sc_proof_of_time::verifier::PotVerifier;
#[cfg(not(feature = "pot"))]
use sc_telemetry::CONSENSUS_DEBUG;
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_TRACE};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use schnorrkel::context::SigningContext;
use sp_api::{ApiExt, BlockT, HeaderT, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::{BlockOrigin, Error as ConsensusError};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    extract_subspace_digest_items, CompatibleDigestItem, PreDigest, SubspaceDigestItems,
};
#[cfg(feature = "pot")]
use sp_consensus_subspace::{ChainConstants, SubspaceJustification};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SubspaceApi};
use sp_runtime::DigestItem;
#[cfg(feature = "pot")]
use sp_runtime::Justifications;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PublicKey, RewardSignature};
use subspace_proof_of_space::Table;
use subspace_solving::REWARD_SIGNING_CONTEXT;
use subspace_verification::{check_reward_signature, verify_solution, VerifySolutionParams};

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
    offchain_tx_pool_factory: OffchainTransactionPoolFactory<Block>,
    is_authoring_blocks: bool,
    #[cfg(feature = "pot")] pot_verifier: PotVerifier,
) -> Result<DefaultImportQueue<Block>, sp_blockchain::Error>
where
    PosTable: Table,
    Inner: BlockImport<Block, Error = ConsensusError> + Send + Sync + 'static,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore + Send + Sync + 'static,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    SelectChain: sp_consensus::SelectChain<Block> + 'static,
    SN: Fn() -> Slot + Send + Sync + 'static,
{
    #[cfg(feature = "pot")]
    let chain_constants = get_chain_constants(client.as_ref())
        .map_err(|error| sp_blockchain::Error::Application(error.into()))?;

    let verifier = SubspaceVerifier {
        client,
        kzg,
        select_chain,
        slot_now,
        telemetry,
        offchain_tx_pool_factory,
        #[cfg(feature = "pot")]
        chain_constants,
        reward_signing_context: schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
        is_authoring_blocks,
        #[cfg(feature = "pot")]
        pot_verifier,
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

/// Errors encountered by the Subspace verification task.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum VerificationError<Header: HeaderT> {
    /// Header has a bad seal
    #[error("Header {0:?} has a bad seal")]
    HeaderBadSeal(Header::Hash),
    /// Header is unsealed
    #[error("Header {0:?} is unsealed")]
    HeaderUnsealed(Header::Hash),
    /// Bad reward signature
    #[error("Bad reward signature on {0:?}")]
    BadRewardSignature(Header::Hash),
    /// Invalid Subspace justification
    #[cfg(feature = "pot")]
    #[error("Invalid Subspace justification: {0}")]
    InvalidSubspaceJustification(codec::Error),
    /// Invalid Subspace justification contents
    #[cfg(feature = "pot")]
    #[error("Invalid Subspace justification contents")]
    InvalidSubspaceJustificationContents,
    /// Invalid proof of time
    #[cfg(feature = "pot")]
    #[error("Invalid proof of time")]
    InvalidProofOfTime,
    /// Verification error
    #[error("Verification error on slot {0:?}: {1:?}")]
    VerificationError(Slot, subspace_verification::Error),
}

/// A header which has been checked
enum CheckedHeader<H, S> {
    /// A header which has slot in the future. this is the full header (not stripped)
    /// and the slot in which it should be processed.
    #[cfg(not(feature = "pot"))]
    Deferred(H, Slot),
    /// A header which is fully checked, including signature. This is the pre-header
    /// accompanied by the seal components.
    ///
    /// Includes the digest item that encoded the seal.
    Checked(H, S),
}

/// Subspace verification parameters
struct VerificationParams<'a, Header>
where
    Header: HeaderT + 'a,
{
    /// The header being verified.
    header: Header,
    /// The slot number of the current time.
    // TODO: Remove field once PoT is the only option
    #[cfg(not(feature = "pot"))]
    slot_now: Slot,
    /// Parameters for solution verification
    verify_solution_params: &'a VerifySolutionParams,
}

/// Information from verified header
struct VerifiedHeaderInfo {
    /// Pre-digest
    pre_digest: PreDigest<FarmerPublicKey, FarmerPublicKey>,
    /// Seal (signature)
    seal: DigestItem,
}

/// A verifier for Subspace blocks.
struct SubspaceVerifier<PosTable, Block: BlockT, Client, SelectChain, SN> {
    client: Arc<Client>,
    kzg: Kzg,
    select_chain: SelectChain,
    // TODO: Remove field once PoT is the only option
    slot_now: SN,
    telemetry: Option<TelemetryHandle>,
    offchain_tx_pool_factory: OffchainTransactionPoolFactory<Block>,
    #[cfg(feature = "pot")]
    chain_constants: ChainConstants,
    reward_signing_context: SigningContext,
    is_authoring_blocks: bool,
    #[cfg(feature = "pot")]
    pot_verifier: PotVerifier,
    _pos_table: PhantomData<PosTable>,
    _block: PhantomData<Block>,
}

impl<PosTable, Block, Client, SelectChain, SN>
    SubspaceVerifier<PosTable, Block, Client, SelectChain, SN>
where
    PosTable: Table,
    Block: BlockT,
    Client: AuxStore + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    SelectChain: sp_consensus::SelectChain<Block>,
{
    /// Check a header has been signed correctly and whether solution is correct. If the slot is too
    /// far in the future, an error will be returned. If successful, returns the pre-header and the
    /// digest item containing the seal.
    ///
    /// The seal must be the last digest. Otherwise, the whole header is considered unsigned. This
    /// is required for security and must not be changed.
    ///
    /// This digest item will always return `Some` when used with `as_subspace_pre_digest`.
    ///
    /// `pre_digest` argument is optional in case it is available to avoid doing the work of
    /// extracting it from the header twice.
    async fn check_header(
        &self,
        params: VerificationParams<'_, Block::Header>,
        subspace_digest_items: SubspaceDigestItems<
            FarmerPublicKey,
            FarmerPublicKey,
            FarmerSignature,
        >,
        #[cfg(feature = "pot")] justifications: &Option<Justifications>,
    ) -> Result<CheckedHeader<Block::Header, VerifiedHeaderInfo>, VerificationError<Block::Header>>
    {
        let VerificationParams {
            mut header,
            #[cfg(not(feature = "pot"))]
            slot_now,
            verify_solution_params,
        } = params;

        let pre_digest = subspace_digest_items.pre_digest;
        let slot = pre_digest.slot();

        let seal = header
            .digest_mut()
            .pop()
            .ok_or_else(|| VerificationError::HeaderUnsealed(header.hash()))?;

        let signature = seal
            .as_subspace_seal()
            .ok_or_else(|| VerificationError::HeaderBadSeal(header.hash()))?;

        // The pre-hash of the header doesn't include the seal and that's what we sign
        let pre_hash = header.hash();

        #[cfg(not(feature = "pot"))]
        if slot > slot_now {
            header.digest_mut().push(seal);
            return Ok(CheckedHeader::Deferred(header, slot));
        }

        // The case where we have justifications is a happy case because we can verify most things
        // right way and more efficiently than without justifications. But justifications are not
        // always available, so fallback is still needed.
        #[cfg(feature = "pot")]
        if let Some(subspace_justification) = justifications.as_ref().and_then(|justifications| {
            justifications
                .iter()
                .find_map(SubspaceJustification::try_from_justification)
        }) {
            let subspace_justification =
                subspace_justification.map_err(VerificationError::InvalidSubspaceJustification)?;

            let SubspaceJustification::PotCheckpoints {
                mut seed,
                checkpoints,
            } = subspace_justification;

            // Last checkpoint must be out future proof of time, this is how we anchor the rest of
            // checks together
            if checkpoints.last().map(|checkpoints| checkpoints.output())
                != Some(pre_digest.pot_info().future_proof_of_time())
            {
                return Err(VerificationError::InvalidSubspaceJustificationContents);
            }

            let future_slot = slot + self.chain_constants.block_authoring_delay();
            let mut slot_to_check = Slot::from(
                future_slot
                    .checked_sub(checkpoints.len() as u64 - 1)
                    .ok_or(VerificationError::InvalidProofOfTime)?,
            );
            let mut slot_iterations = subspace_digest_items
                .pot_parameters_change
                .as_ref()
                .and_then(|parameters_change| {
                    (parameters_change.slot == slot_to_check)
                        .then_some(parameters_change.slot_iterations)
                })
                .unwrap_or(subspace_digest_items.pot_slot_iterations);

            // All checkpoints must be valid, at least according to the seed included in
            // justifications
            let verification_results = FuturesUnordered::new();
            for checkpoints in &checkpoints {
                verification_results.push(self.pot_verifier.verify_checkpoints(
                    seed,
                    slot_iterations,
                    checkpoints,
                ));

                slot_to_check = slot_to_check + Slot::from(1);
                if let Some(parameters_change) = subspace_digest_items.pot_parameters_change
                    && parameters_change.slot == slot_to_check
                {
                    slot_iterations = parameters_change.slot_iterations;
                    seed = checkpoints
                        .output()
                        .seed_with_entropy(&parameters_change.entropy);
                } else {
                    seed = checkpoints.output().seed();
                }
            }
            // Try to find invalid checkpoints
            if verification_results
                // TODO: Ideally we'd use `find` here instead, but it does not yet exists:
                //  https://github.com/rust-lang/futures-rs/issues/2705
                .filter(|&success| async move { !success })
                .boxed()
                .next()
                .await
                .is_some()
            {
                return Err(VerificationError::InvalidProofOfTime);
            }

            // Below verification that doesn't depend on justifications will be running more
            // efficient due to correct checkpoints cached as the result of justification
            // verification
        }

        #[cfg(feature = "pot")]
        let slot_iterations;
        #[cfg(feature = "pot")]
        let pot_seed;
        #[cfg(feature = "pot")]
        let next_slot = slot + Slot::from(1);
        #[cfg(feature = "pot")]
        // The change to number of iterations might have happened before `next_slot`
        if let Some(parameters_change) = subspace_digest_items.pot_parameters_change
            && parameters_change.slot <= next_slot
        {
            slot_iterations = parameters_change.slot_iterations;
            // Only if entropy injection happens exactly on next slot we need to mix it in
            if parameters_change.slot == next_slot {
                pot_seed = pre_digest
                    .pot_info()
                    .proof_of_time()
                    .seed_with_entropy(&parameters_change.entropy);
            } else {
                pot_seed = pre_digest.pot_info().proof_of_time().seed();
            }
        } else {
            slot_iterations = subspace_digest_items.pot_slot_iterations;
            pot_seed = pre_digest.pot_info().proof_of_time().seed();
        }

        // Check proof of time between slot of the block and future proof of time.
        //
        // Here during stateless verification we do not have access to parent block, thus only
        // verify proofs after proof of time of at current slot up until future proof of time
        // (inclusive), during block import we verify the rest.
        #[cfg(feature = "pot")]
        if !self
            .pot_verifier
            .is_output_valid(
                next_slot,
                pot_seed,
                slot_iterations,
                self.chain_constants.block_authoring_delay(),
                pre_digest.pot_info().future_proof_of_time(),
                subspace_digest_items.pot_parameters_change,
            )
            .await
        {
            return Err(VerificationError::InvalidProofOfTime);
        }

        // Verify that block is signed properly
        if check_reward_signature(
            pre_hash.as_ref(),
            &RewardSignature::from(&signature),
            &PublicKey::from(&pre_digest.solution().public_key),
            &self.reward_signing_context,
        )
        .is_err()
        {
            return Err(VerificationError::BadRewardSignature(pre_hash));
        }

        // Verify that solution is valid
        verify_solution::<PosTable, _, _>(
            pre_digest.solution(),
            slot.into(),
            verify_solution_params,
            &self.kzg,
        )
        .map_err(|error| VerificationError::VerificationError(slot, error))?;

        Ok(CheckedHeader::Checked(
            header,
            VerifiedHeaderInfo { pre_digest, seal },
        ))
    }

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
            let mut runtime_api = self.client.runtime_api();
            // Register the offchain tx pool to be able to use it from the runtime.
            runtime_api.register_extension(
                self.offchain_tx_pool_factory
                    .offchain_transaction_pool(best_hash),
            );
            runtime_api
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
        mut block: BlockImportParams<Block>,
    ) -> Result<BlockImportParams<Block>, String> {
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

        // Check if farmer's plot is burned.
        // TODO: Add to header and store in aux storage?
        if self
            .client
            .runtime_api()
            .is_in_block_list(
                *block.header.parent_hash(),
                &subspace_digest_items.pre_digest.solution().public_key,
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
                subspace_digest_items.pre_digest.solution().public_key
            );

            return Err(Error::<Block::Header>::FarmerInBlockList(
                subspace_digest_items
                    .pre_digest
                    .solution()
                    .public_key
                    .clone(),
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
        let checked_header = self
            .check_header(
                VerificationParams {
                    header: block.header.clone(),
                    #[cfg(not(feature = "pot"))]
                    slot_now: slot_now + 1,
                    verify_solution_params: &VerifySolutionParams {
                        #[cfg(not(feature = "pot"))]
                        global_randomness: subspace_digest_items.global_randomness,
                        #[cfg(feature = "pot")]
                        proof_of_time: subspace_digest_items.pre_digest.pot_info().proof_of_time(),
                        solution_range: subspace_digest_items.solution_range,
                        piece_check_params: None,
                    },
                },
                subspace_digest_items,
                #[cfg(feature = "pot")]
                &block.justifications,
            )
            .await
            .map_err(Error::<Block::Header>::from)?;

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
            #[cfg(not(feature = "pot"))]
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
