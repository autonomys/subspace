use sc_consensus_slots::SlotInfo;
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::{Block as BlockT, Header};
use std::time::Duration;
use tracing::error;

pub(super) struct SlotInfoProducer<Block, SC, IDP> {
    slot_duration: Duration,
    create_inherent_data_providers: IDP,
    select_chain: SC,
    _phantom: std::marker::PhantomData<Block>,
}

impl<Block, SC, IDP> SlotInfoProducer<Block, SC, IDP> {
    /// Create a new `Slots` stream.
    pub(super) fn new(
        slot_duration: Duration,
        create_inherent_data_providers: IDP,
        select_chain: SC,
    ) -> Self {
        SlotInfoProducer {
            slot_duration,
            create_inherent_data_providers,
            select_chain,
            _phantom: Default::default(),
        }
    }
}

impl<Block, SC, IDP> SlotInfoProducer<Block, SC, IDP>
where
    Block: BlockT,
    SC: SelectChain<Block>,
    IDP: CreateInherentDataProviders<Block, ()> + 'static,
{
    pub(super) async fn produce_slot_info(&self, slot: Slot) -> Option<SlotInfo<Block>> {
        let best_header = match self.select_chain.best_chain().await {
            Ok(best_header) => best_header,
            Err(error) => {
                error!(
                    %error,
                    "Unable to author block in slot. No best block header.",
                );

                return None;
            }
        };

        let inherent_data_providers = match self
            .create_inherent_data_providers
            .create_inherent_data_providers(best_header.hash(), ())
            .await
        {
            Ok(inherent_data_providers) => inherent_data_providers,
            Err(error) => {
                error!(
                    %error,
                    "Unable to author block in slot. Failure creating inherent data provider.",
                );

                return None;
            }
        };

        Some(SlotInfo::new(
            slot,
            Box::new(inherent_data_providers),
            self.slot_duration,
            best_header,
            None,
        ))
    }
}
