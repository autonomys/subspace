// This file is part of Substrate.

// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Domain Executive Module
//!
//! This module is derived from frame_executive with some custom modifications for
//! collecting the intermediate storage roots in the block execution required for
//! the fraud proof of decoupled execution in Subspace.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub mod weights;

use codec::Codec;
use frame_support::dispatch::{DispatchClass, DispatchInfo, GetDispatchInfo, PostDispatchInfo};
use frame_support::traits::{
    EnsureInherentsAreFirst, ExecuteBlock, Get, OffchainWorker, OnFinalize, OnIdle, OnInitialize,
    OnRuntimeUpgrade,
};
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;
pub use pallet::*;
use sp_runtime::traits::{
    self, Applyable, CheckEqual, Checkable, Dispatchable, Header, NumberFor, One, ValidateUnsigned,
    Zero,
};
use sp_runtime::transaction_validity::{TransactionSource, TransactionValidity};
use sp_runtime::ApplyExtrinsicResult;
use sp_std::marker::PhantomData;
use sp_std::prelude::*;

pub type CheckedOf<E, C> = <E as Checkable<C>>::Checked;
pub type CallOf<E, C> = <CheckedOf<E, C> as Applyable>::Call;
pub type OriginOf<E, C> = <CallOf<E, C> as Dispatchable>::RuntimeOrigin;

// TODO: not store the intermediate storage root in the state but
// calculate the storage root outside the runtime after executing the extrinsic directly.
#[frame_support::pallet]
mod pallet {
    use crate::weights::WeightInfo;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use frame_system::SetCode;
    use sp_executive::{InherentError, InherentType, INHERENT_IDENTIFIER};
    use sp_std::vec::Vec;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Sets new runtime code after doing necessary checks.
        /// Same as frame_system::Call::set_code but without root origin.
        #[pallet::call_index(0)]
        #[pallet::weight((T::WeightInfo::set_code(), DispatchClass::Mandatory))]
        pub fn set_code(origin: OriginFor<T>, code: Vec<u8>) -> DispatchResult {
            ensure_none(origin)?;
            <frame_system::pallet::Pallet<T>>::can_set_code(&code)?;
            <T as frame_system::Config>::OnSetCode::set_code(code)?;
            Ok(())
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

        fn create_inherent(data: &InherentData) -> Option<Self::Call> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Executive inherent data not correctly encoded")
                .expect("Executive inherent data must be provided");

            inherent_data.maybe_code.map(|code| Call::set_code { code })
        }

        fn is_inherent_required(data: &InherentData) -> Result<Option<Self::Error>, Self::Error> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Executive inherent data not correctly encoded")
                .expect("Executive inherent data must be provided");

            Ok(if inherent_data.maybe_code.is_none() {
                None
            } else {
                Some(InherentError::MissingRuntimeCode)
            })
        }

        fn check_inherent(call: &Self::Call, data: &InherentData) -> Result<(), Self::Error> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Executive inherent data not correctly encoded")
                .expect("Executive inherent data must be provided");

            if let Some(provided_code) = inherent_data.maybe_code {
                if let Call::set_code { code } = call {
                    if code != &provided_code {
                        return Err(InherentError::IncorrectRuntimeCode);
                    }
                }
            } else {
                return Err(InherentError::MissingRuntimeCode);
            }

            Ok(())
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::set_code { .. })
        }
    }

    #[pallet::event]
    pub enum Event<T: Config> {}

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_block_number: BlockNumberFor<T>) -> Weight {
            // Reset the intermediate storage roots from last block.
            IntermediateRoots::<T>::kill();
            // TODO: Probably needs a different value
            Weight::from_parts(1, 0)
        }
    }

    /// Intermediate storage roots collected during the block execution.
    #[pallet::storage]
    #[pallet::getter(fn intermediate_roots)]
    pub(super) type IntermediateRoots<T: Config> = StorageValue<_, Vec<[u8; 32]>, ValueQuery>;
}

impl<T: Config> Pallet<T> {
    pub(crate) fn push_root(root: Vec<u8>) {
        IntermediateRoots::<T>::append(
            TryInto::<[u8; 32]>::try_into(root)
                .expect("root is a SCALE encoded hash which uses H256; qed"),
        );
    }
}

/// Same semantics with `frame_executive::Executive`.
///
/// One extra generic parameter:
/// - `ExecutiveConfig`: Something that implements `domain_pallet_executive::Config`.
pub struct Executive<
    System,
    Block,
    Context,
    UnsignedValidator,
    AllPalletsWithSystem,
    ExecutiveConfig,
    OnRuntimeUpgrade = (),
>(
    PhantomData<(
        System,
        Block,
        Context,
        UnsignedValidator,
        AllPalletsWithSystem,
        ExecutiveConfig,
        OnRuntimeUpgrade,
    )>,
);

impl<
        System: frame_system::Config + EnsureInherentsAreFirst<Block>,
        Block: traits::Block<Header = HeaderFor<System>, Hash = System::Hash>,
        Context: Default,
        UnsignedValidator,
        AllPalletsWithSystem: OnRuntimeUpgrade
            + OnInitialize<BlockNumberFor<System>>
            + OnIdle<BlockNumberFor<System>>
            + OnFinalize<BlockNumberFor<System>>
            + OffchainWorker<BlockNumberFor<System>>,
        ExecutiveConfig: Config,
        COnRuntimeUpgrade: OnRuntimeUpgrade,
    > ExecuteBlock<Block>
    for Executive<
        System,
        Block,
        Context,
        UnsignedValidator,
        AllPalletsWithSystem,
        ExecutiveConfig,
        COnRuntimeUpgrade,
    >
where
    Block::Extrinsic: Checkable<Context> + Codec,
    CheckedOf<Block::Extrinsic, Context>: Applyable + GetDispatchInfo,
    CallOf<Block::Extrinsic, Context>:
        Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    OriginOf<Block::Extrinsic, Context>: From<Option<System::AccountId>>,
    UnsignedValidator: ValidateUnsigned<Call = CallOf<Block::Extrinsic, Context>>,
{
    fn execute_block(block: Block) {
        Executive::<
            System,
            Block,
            Context,
            UnsignedValidator,
            AllPalletsWithSystem,
            ExecutiveConfig,
            COnRuntimeUpgrade,
        >::execute_block(block);
    }
}

impl<
        System: frame_system::Config + EnsureInherentsAreFirst<Block>,
        Block: traits::Block<Header = HeaderFor<System>, Hash = System::Hash>,
        Context: Default,
        UnsignedValidator,
        AllPalletsWithSystem: OnRuntimeUpgrade
            + OnInitialize<BlockNumberFor<System>>
            + OnIdle<BlockNumberFor<System>>
            + OnFinalize<BlockNumberFor<System>>
            + OffchainWorker<BlockNumberFor<System>>,
        ExecutiveConfig: Config,
        COnRuntimeUpgrade: OnRuntimeUpgrade,
    >
    Executive<
        System,
        Block,
        Context,
        UnsignedValidator,
        AllPalletsWithSystem,
        ExecutiveConfig,
        COnRuntimeUpgrade,
    >
where
    Block::Extrinsic: Checkable<Context> + Codec,
    CheckedOf<Block::Extrinsic, Context>: Applyable + GetDispatchInfo,
    CallOf<Block::Extrinsic, Context>:
        Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
    OriginOf<Block::Extrinsic, Context>: From<Option<System::AccountId>>,
    UnsignedValidator: ValidateUnsigned<Call = CallOf<Block::Extrinsic, Context>>,
{
    /// Returns the latest storage root.
    pub fn storage_root() -> Vec<u8> {
        let version = System::Version::get().state_version();
        sp_io::storage::root(version)
    }

    /// Wrapped `frame_executive::Executive::execute_on_runtime_upgrade`.
    pub fn execute_on_runtime_upgrade() -> Weight {
        frame_executive::Executive::<
            System,
            Block,
            Context,
            UnsignedValidator,
            AllPalletsWithSystem,
            COnRuntimeUpgrade,
        >::execute_on_runtime_upgrade()
    }

    /// Wrapped `frame_executive::Executive::execute_block_no_check`.
    #[cfg(feature = "try-runtime")]
    pub fn execute_block_no_check(block: Block) -> Weight {
        frame_executive::Executive::<
            System,
            Block,
            Context,
            UnsignedValidator,
            AllPalletsWithSystem,
            COnRuntimeUpgrade,
        >::execute_block_no_check(block)
    }

    /// Wrapped `frame_executive::Executive::try_runtime_upgrade`.
    #[cfg(feature = "try-runtime")]
    pub fn try_runtime_upgrade() -> Result<Weight, &'static str> {
        frame_executive::Executive::<
            System,
            Block,
            Context,
            UnsignedValidator,
            AllPalletsWithSystem,
            COnRuntimeUpgrade,
        >::try_runtime_upgrade()
    }

    /// Wrapped `frame_executive::Executive::initialize_block`.
    ///
    /// Note the storage root in the end.
    pub fn initialize_block(header: &HeaderFor<System>) {
        frame_executive::Executive::<
            System,
            Block,
            Context,
            UnsignedValidator,
            AllPalletsWithSystem,
            COnRuntimeUpgrade,
        >::initialize_block(header);
    }

    // TODO: https://github.com/paritytech/substrate/issues/10711
    fn initial_checks(block: &Block) {
        sp_tracing::enter_span!(sp_tracing::Level::TRACE, "initial_checks");
        let header = block.header();

        // Check that `parent_hash` is correct.
        let n = *header.number();
        assert!(
            n > BlockNumberFor::<System>::zero()
                && <frame_system::Pallet<System>>::block_hash(n - BlockNumberFor::<System>::one())
                    == *header.parent_hash(),
            "Parent hash should be valid.",
        );

        if let Err(i) = System::ensure_inherents_are_first(block) {
            panic!("Invalid inherent position for extrinsic at index {i}");
        }
    }

    /// Wrapped `frame_executive::Executive::execute_block`.
    ///
    /// The purpose is to use our custom [`Executive::initialize_block`] and
    /// [`Executive::apply_extrinsic`].
    pub fn execute_block(block: Block) {
        sp_io::init_tracing();
        sp_tracing::within_span! {
            sp_tracing::info_span!("execute_block", ?block);

            Self::initialize_block(block.header());

            Self::initial_checks(&block);

            // execute extrinsics
            let (header, extrinsics) = block.deconstruct();
            Self::execute_extrinsics_with_book_keeping(extrinsics, *header.number());

            Self::final_checks(&header);
        }
    }

    /// Exactly same with `frame_executive::executive::execute_extrinsics_with_book_keeping`.
    fn execute_extrinsics_with_book_keeping(
        extrinsics: Vec<Block::Extrinsic>,
        block_number: NumberFor<Block>,
    ) {
        extrinsics.into_iter().for_each(|e| {
            if let Err(e) = Self::apply_extrinsic(e) {
                let err: &'static str = e.into();
                panic!("{}", err)
            }
        });

        // Note the storage root before finalizing the block so that the block imported during the
        // syncing processs produces the same storage root with the one processed based on
        // the consensus block.
        Pallet::<ExecutiveConfig>::push_root(Self::storage_root());

        // post-extrinsics book-keeping
        <frame_system::Pallet<System>>::note_finished_extrinsics();

        Self::idle_and_finalize_hook(block_number);
    }

    /// Wrapped `frame_executive::Executive::finalize_block`.
    pub fn finalize_block() -> HeaderFor<System> {
        Pallet::<ExecutiveConfig>::push_root(Self::storage_root());
        frame_executive::Executive::<
            System,
            Block,
            Context,
            UnsignedValidator,
            AllPalletsWithSystem,
            COnRuntimeUpgrade,
        >::finalize_block()
    }

    // TODO: https://github.com/paritytech/substrate/issues/10711
    fn idle_and_finalize_hook(block_number: NumberFor<Block>) {
        let weight = <frame_system::Pallet<System>>::block_weight();
        let max_weight = <System::BlockWeights as frame_support::traits::Get<_>>::get().max_block;
        let remaining_weight = max_weight.saturating_sub(weight.total());

        if remaining_weight.all_gt(Weight::zero()) {
            let used_weight = <AllPalletsWithSystem as OnIdle<BlockNumberFor<System>>>::on_idle(
                block_number,
                remaining_weight,
            );
            <frame_system::Pallet<System>>::register_extra_weight_unchecked(
                used_weight,
                DispatchClass::Mandatory,
            );
        }

        <AllPalletsWithSystem as OnFinalize<BlockNumberFor<System>>>::on_finalize(block_number);
    }

    /// Wrapped `frame_executive::Executive::apply_extrinsic`.
    ///
    /// Note the storage root in the end.
    pub fn apply_extrinsic(uxt: Block::Extrinsic) -> ApplyExtrinsicResult {
        Pallet::<ExecutiveConfig>::push_root(Self::storage_root());
        let res = frame_executive::Executive::<
            System,
            Block,
            Context,
            UnsignedValidator,
            AllPalletsWithSystem,
            COnRuntimeUpgrade,
        >::apply_extrinsic(uxt);
        // TODO: Critical!!! https://github.com/paritytech/substrate/pull/10922#issuecomment-1068997467
        log::info!(
            target: "domain::runtime::executive",
            "[apply_extrinsic] after: {:?}",
            {
                use codec::Decode;
                Block::Hash::decode(&mut Self::storage_root().as_slice()).unwrap()
            }
        );
        res
    }

    // TODO: https://github.com/paritytech/substrate/issues/10711
    fn final_checks(header: &HeaderFor<System>) {
        sp_tracing::enter_span!(sp_tracing::Level::TRACE, "final_checks");
        // remove temporaries
        let new_header = <frame_system::Pallet<System>>::finalize();

        // check digest
        assert_eq!(
            header.digest().logs().len(),
            new_header.digest().logs().len(),
            "Number of digest items must match that calculated."
        );
        let items_zip = header
            .digest()
            .logs()
            .iter()
            .zip(new_header.digest().logs().iter());
        for (header_item, computed_item) in items_zip {
            header_item.check_equal(computed_item);
            assert_eq!(
                header_item, computed_item,
                "Digest item must match that calculated."
            );
        }

        // check storage root.
        let storage_root = new_header.state_root();
        header.state_root().check_equal(storage_root);
        assert!(
            header.state_root() == storage_root,
            "Storage root must match that calculated."
        );

        assert!(
            header.extrinsics_root() == new_header.extrinsics_root(),
            "Transaction trie root must be valid.",
        );
    }

    /// Wrapped `frame_executive::Executive::validate_transaction`.
    pub fn validate_transaction(
        source: TransactionSource,
        uxt: Block::Extrinsic,
        block_hash: Block::Hash,
    ) -> TransactionValidity {
        frame_executive::Executive::<
            System,
            Block,
            Context,
            UnsignedValidator,
            AllPalletsWithSystem,
            COnRuntimeUpgrade,
        >::validate_transaction(source, uxt, block_hash)
    }

    /// Wrapped `frame_executive::Executive::offchain_worker`.
    pub fn offchain_worker(header: &HeaderFor<System>) {
        frame_executive::Executive::<
            System,
            Block,
            Context,
            UnsignedValidator,
            AllPalletsWithSystem,
            COnRuntimeUpgrade,
        >::offchain_worker(header)
    }
}
