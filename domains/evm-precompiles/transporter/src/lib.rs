//! Transporter precompile
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

use core::marker::PhantomData;
use domain_runtime_primitives::MultiAccountId;
use fp_evm::Log;
use frame_support::dispatch::{GetDispatchInfo, PostDispatchInfo};
use frame_support::traits::OriginTrait;
use pallet_evm::AddressMapping;
use pallet_transporter::{BalanceOf, Location};
use parity_scale_codec::Decode;
use precompile_utils::prelude::*;
use precompile_utils::solidity;
use sp_core::crypto::AccountId32;
use sp_core::{Get, H160, H256, U256};
use sp_messenger::messages::ChainId;
use sp_runtime::traits::Dispatchable;

pub struct TransporterPrecompile<Runtime>(PhantomData<Runtime>);

/// Solidity selector of the Transfer to Consensus log.
pub const SELECTOR_LOG_TRANSFER_TO_CONSENSUS: [u8; 32] =
    keccak256!("TransferToConsensus(address,bytes32,u256)");

pub fn log_transfer_to_consensus(address: H160, who: H160, receiver: H256, amount: U256) -> Log {
    log3(
        address,
        SELECTOR_LOG_TRANSFER_TO_CONSENSUS,
        who,
        receiver,
        solidity::encode_event_data(amount),
    )
}

#[precompile]
impl<Runtime> TransporterPrecompile<Runtime>
where
    Runtime: pallet_evm::Config + pallet_transporter::Config,
    Runtime::RuntimeCall: Dispatchable<PostInfo = PostDispatchInfo> + GetDispatchInfo + Decode,
    <Runtime as pallet_evm::Config>::AddressMapping: AddressMapping<Runtime::AccountId>,
    Runtime::RuntimeCall: From<pallet_transporter::Call<Runtime>>,
    BalanceOf<Runtime>: From<u128> + Into<u128>,
{
    #[precompile::public("transfer_to_consensus_v1(bytes32,u256)")]
    fn transfer_to_consensus_v1(
        handle: &mut impl PrecompileHandle,
        receiver: H256,
        amount: Convert<U256, u128>,
    ) -> EvmResult {
        let amount = amount.converted();

        let event = log_transfer_to_consensus(
            handle.context().address,
            handle.context().caller,
            receiver,
            amount.into(),
        );
        handle.record_log_costs(&[&event])?;

        let receiver = AccountId32::new(receiver.0);
        let amount: BalanceOf<Runtime> = amount.into();

        let origin = Runtime::RuntimeOrigin::signed(Runtime::AddressMapping::into_account_id(
            handle.context().caller,
        ));

        RuntimeHelper::<Runtime>::try_dispatch(
            handle,
            origin,
            pallet_transporter::Call::<Runtime>::transfer {
                dst_location: Location {
                    chain_id: ChainId::Consensus,
                    account_id: MultiAccountId::AccountId32(receiver.into()),
                },
                amount,
            },
            // we do not need to account for additional storage growth
            0,
        )?;

        event.record(handle)?;

        Ok(())
    }

    #[precompile::public("minimum_transfer_amount()")]
    #[precompile::view]
    fn minimum_transfer_amount(_handle: &mut impl PrecompileHandle) -> EvmResult<U256> {
        let min_transfer = <Runtime as pallet_transporter::Config>::MinimumTransfer::get();
        Ok(U256::from(min_transfer.into()))
    }
}
