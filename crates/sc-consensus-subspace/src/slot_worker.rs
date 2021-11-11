// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::*;

pub(super) struct SubspaceSlotWorker<B: BlockT, C, E, I, SO, L, BS> {
    pub(super) client: Arc<C>,
    pub(super) block_import: I,
    pub(super) env: E,
    pub(super) sync_oracle: SO,
    pub(super) justification_sync_link: L,
    pub(super) force_authoring: bool,
    pub(super) backoff_authoring_blocks: Option<BS>,
    pub(super) subspace_link: SubspaceLink<B>,
    pub(super) signing_context: SigningContext,
    pub(super) block_proposal_slot_portion: SlotProportion,
    pub(super) max_block_proposal_slot_portion: Option<SlotProportion>,
    pub(super) telemetry: Option<TelemetryHandle>,
}

#[async_trait::async_trait]
impl<B, C, E, I, Error, SO, L, BS> SimpleSlotWorker<B> for SubspaceSlotWorker<B, C, E, I, SO, L, BS>
where
    B: BlockT,
    C: ProvideRuntimeApi<B>
        + ProvideCache<B>
        + HeaderBackend<B>
        + HeaderMetadata<B, Error = ClientError>
        + 'static,
    C::Api: SubspaceApi<B>,
    E: Environment<B, Error = Error> + Send + Sync,
    E::Proposer: Proposer<B, Error = Error, Transaction = sp_api::TransactionFor<C, B>>,
    I: BlockImport<B, Transaction = sp_api::TransactionFor<C, B>> + Send + Sync + 'static,
    SO: SyncOracle + Send + Sync + Clone,
    L: sc_consensus::JustificationSyncLink<B>,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<B>> + Send + Sync,
    Error: std::error::Error + Send + From<ConsensusError> + From<I::Error> + 'static,
{
    type EpochData = ViableEpochDescriptor<B::Hash, NumberFor<B>, Epoch>;
    type Claim = (PreDigest, Pair);
    type SyncOracle = SO;
    type JustificationSyncLink = L;
    type CreateProposer =
        Pin<Box<dyn Future<Output = Result<E::Proposer, sp_consensus::Error>> + Send + 'static>>;
    type Proposer = E::Proposer;
    type BlockImport = I;

    fn logging_target(&self) -> &'static str {
        "subspace"
    }

    fn block_import(&mut self) -> &mut Self::BlockImport {
        &mut self.block_import
    }

    fn epoch_data(
        &self,
        parent: &B::Header,
        slot: Slot,
    ) -> Result<Self::EpochData, ConsensusError> {
        self.subspace_link
            .epoch_changes
            .shared_data()
            .epoch_descriptor_for_child_of(
                descendent_query(&*self.client),
                &parent.hash(),
                *parent.number(),
                slot,
            )
            .map_err(|e| ConsensusError::ChainLookup(format!("{:?}", e)))?
            .ok_or(sp_consensus::Error::InvalidAuthoritiesSet)
    }

    async fn claim_slot(
        &self,
        parent_header: &B::Header,
        slot: Slot,
        epoch_descriptor: &Self::EpochData,
    ) -> Option<Self::Claim> {
        self.claim_slot_impl(parent_header, slot, epoch_descriptor)
            .await
    }

    fn pre_digest_data(
        &self,
        _slot: Slot,
        claim: &Self::Claim,
    ) -> Vec<sp_runtime::DigestItem<B::Hash>> {
        vec![<DigestItemFor<B> as CompatibleDigestItem>::subspace_pre_digest(claim.0.clone())]
    }

    #[allow(clippy::type_complexity)]
    fn block_import_params(
        &self,
    ) -> Box<
        dyn Fn(
                B::Header,
                &B::Hash,
                Vec<B::Extrinsic>,
                StorageChanges<I::Transaction, B>,
                Self::Claim,
                Self::EpochData,
            )
                -> Result<sc_consensus::BlockImportParams<B, I::Transaction>, sp_consensus::Error>
            + Send
            + 'static,
    > {
        Box::new(
            move |header,
                  header_hash,
                  body,
                  storage_changes,
                  (_pre_digest, keypair),
                  epoch_descriptor| {
                // sign the pre-sealed hash of the block and then
                // add it to a digest item.
                let signature = keypair.sign(header_hash.as_ref());
                let digest_item =
                    <DigestItemFor<B> as CompatibleDigestItem>::subspace_seal(signature.into());

                let mut import_block = BlockImportParams::new(BlockOrigin::Own, header);
                import_block.post_digests.push(digest_item);
                import_block.body = Some(body);
                import_block.state_action = StateAction::ApplyChanges(
                    sc_consensus::StorageChanges::Changes(storage_changes),
                );
                import_block.intermediates.insert(
                    Cow::from(INTERMEDIATE_KEY),
                    Box::new(SubspaceIntermediate::<B> { epoch_descriptor }) as Box<_>,
                );

                Ok(import_block)
            },
        )
    }

    fn force_authoring(&self) -> bool {
        self.force_authoring
    }

    fn should_backoff(&self, slot: Slot, chain_head: &B::Header) -> bool {
        if let Some(ref strategy) = self.backoff_authoring_blocks {
            if let Ok(chain_head_slot) = find_pre_digest::<B>(chain_head).map(|digest| digest.slot)
            {
                return strategy.should_backoff(
                    *chain_head.number(),
                    chain_head_slot,
                    self.client.info().finalized_number,
                    slot,
                    self.logging_target(),
                );
            }
        }
        false
    }

    fn sync_oracle(&mut self) -> &mut Self::SyncOracle {
        &mut self.sync_oracle
    }

    fn justification_sync_link(&mut self) -> &mut Self::JustificationSyncLink {
        &mut self.justification_sync_link
    }

    fn proposer(&mut self, block: &B::Header) -> Self::CreateProposer {
        Box::pin(
            self.env
                .init(block)
                .map_err(|e| sp_consensus::Error::ClientImport(format!("{:?}", e))),
        )
    }

    fn telemetry(&self) -> Option<TelemetryHandle> {
        self.telemetry.clone()
    }

    fn proposing_remaining_duration(&self, slot_info: &SlotInfo<B>) -> std::time::Duration {
        let parent_slot = find_pre_digest::<B>(&slot_info.chain_head)
            .ok()
            .map(|d| d.slot);

        sc_consensus_slots::proposing_remaining_duration(
            parent_slot,
            slot_info,
            &self.block_proposal_slot_portion,
            self.max_block_proposal_slot_portion.as_ref(),
            sc_consensus_slots::SlotLenienceType::Exponential,
            self.logging_target(),
        )
    }

    fn authorities_len(&self, _epoch_data: &Self::EpochData) -> Option<usize> {
        None
    }
}
