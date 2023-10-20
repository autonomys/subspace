// Copyright (C) 2021 Subspace Labs, Inc.
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

//! Common primitives for subspace domain runtime.

#![cfg_attr(not(feature = "std"), no_std)]

use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::generic::{Era, UncheckedExtrinsic};
use sp_runtime::traits::{
    Block as BlockT, Convert, IdentifyAccount, LookupError, NumberFor, Verify,
};
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_runtime::{Digest, MultiAddress, MultiSignature};
use sp_std::vec::Vec;
use sp_weights::Weight;
use subspace_core_primitives::U256;
use subspace_runtime_primitives::Moment;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Nonce = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// An index to a block.
pub type BlockNumber = u32;

/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, ()>;

/// Slot duration that is same as consensus chain runtime.
pub const SLOT_DURATION: u64 = 1000;

/// Extracts the signer from an unchecked extrinsic.
///
/// Used by executor to extract the optional signer when shuffling the extrinsics.
pub trait Signer<AccountId, Lookup> {
    /// Returns the AccountId of signer.
    fn signer(&self, lookup: &Lookup) -> Option<AccountId>;
}

impl<Address, AccountId, Call, Signature, Extra, Lookup> Signer<AccountId, Lookup>
    for UncheckedExtrinsic<Address, Call, Signature, Extra>
where
    Address: Clone,
    Extra: sp_runtime::traits::SignedExtension<AccountId = AccountId>,
    Lookup: sp_runtime::traits::Lookup<Source = Address, Target = AccountId>,
{
    fn signer(&self, lookup: &Lookup) -> Option<AccountId> {
        self.signature
            .as_ref()
            .and_then(|(signed, _, _)| lookup.lookup(signed.clone()).ok())
    }
}

/// MultiAccountId used by all the domains to describe their account type.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum MultiAccountId {
    /// 32 byte account Id.
    AccountId32([u8; 32]),
    /// 20 byte account Id. Ex: Ethereum
    AccountId20([u8; 20]),
    /// Some raw bytes
    Raw(Vec<u8>),
}

/// Extensible conversion trait. Generic over both source and destination types.
pub trait TryConvertBack<A, B>: Convert<A, B> {
    /// Make conversion back.
    fn try_convert_back(b: B) -> Option<A>;
}

/// An AccountId32 to MultiAccount converter.
pub struct AccountIdConverter;

impl Convert<AccountId, MultiAccountId> for AccountIdConverter {
    fn convert(account_id: AccountId) -> MultiAccountId {
        MultiAccountId::AccountId32(account_id.into())
    }
}

impl TryConvertBack<AccountId, MultiAccountId> for AccountIdConverter {
    fn try_convert_back(multi_account_id: MultiAccountId) -> Option<AccountId> {
        match multi_account_id {
            MultiAccountId::AccountId32(acc) => Some(AccountId::new(acc)),
            _ => None,
        }
    }
}

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use crate::BlockNumber;
    use sp_runtime::generic;
    use sp_runtime::traits::BlakeTwo256;
    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;
    use sp_std::vec::Vec;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;
    /// Opaque account identifier type.
    pub type AccountId = Vec<u8>;
}

#[derive(Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum CheckTxValidityError {
    /// Can not find the sender from address.
    Lookup,
    /// Unable to extract signer from tx
    UnableToExtractSigner { error: TransactionValidityError },
    /// Transaction is invalid.
    InvalidTransaction {
        /// Concrete transaction validity error type.
        error: TransactionValidityError,
        /// Storage keys of state accessed in the validation.
        storage_keys: Vec<Vec<u8>>,
    },
}

impl From<LookupError> for CheckTxValidityError {
    fn from(_lookup_error: LookupError) -> Self {
        Self::Lookup
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum VerifyTxValidityError {
    /// Failed to decode the opaque account id into the runtime account type.
    FailedToDecodeAccountId,
}

sp_api::decl_runtime_apis! {
    /// Base API that every domain runtime must implement.
    pub trait DomainCoreApi {
        /// Extracts the optional signer per extrinsic.
        fn extract_signer(
            extrinsics: Vec<<Block as BlockT>::Extrinsic>,
        ) -> Vec<(Option<opaque::AccountId>, <Block as BlockT>::Extrinsic)>;

        fn is_within_tx_range(
            extrinsic: &<Block as BlockT>::Extrinsic,
            bundle_vrf_hash: &U256,
            tx_range: &U256,
        ) -> bool;

        /// Returns the intermediate storage roots in an encoded form.
        fn intermediate_roots() -> Vec<[u8; 32]>;

        /// Returns the storage root after initializing the block.
        fn initialize_block_with_post_state_root(header: &<Block as BlockT>::Header) -> Vec<u8>;

        /// Returns the storage root after applying the extrinsic.
        fn apply_extrinsic_with_post_state_root(extrinsic: <Block as BlockT>::Extrinsic) -> Vec<u8>;

        /// Returns an encoded extrinsic aiming to upgrade the runtime using given code.
        fn construct_set_code_extrinsic(code: Vec<u8>) -> Vec<u8>;

        /// Returns an encoded extrinsic to set timestamp.
        fn construct_timestamp_extrinsic(moment: Moment) -> Block::Extrinsic;

        /// Returns true if the extrinsic is an inherent extrinsic.
        fn is_inherent_extrinsic(extrinsic: &<Block as BlockT>::Extrinsic) -> bool;

        /// Checks the validity of extrinsic in a bundle.
        fn check_transaction_validity(
            uxt: &<Block as BlockT>::Extrinsic,
            block_number: NumberFor<Block>,
            block_hash: <Block as BlockT>::Hash
        ) -> Result<(), CheckTxValidityError>;

        /// Returns the storage keys of states accessed in the API `check_transaction_validity`.
        fn storage_keys_for_verifying_transaction_validity(
            account_id: opaque::AccountId,
            block_number: NumberFor<Block>,
            tx_era: Option<Era>,
        ) -> Result<Vec<Vec<u8>>, VerifyTxValidityError>;

        /// Returns extrinsic Era if present
        fn extrinsic_era(
          extrinsic: &<Block as BlockT>::Extrinsic
        ) -> Option<Era>;

        /// Return the extrinsic weight
        fn extrinsic_weight(ext: &Block::Extrinsic) -> Weight;

        /// The accumulated transaction fee of all transactions included in the block
        fn block_rewards() -> Balance;

        /// Return the block digest
        fn block_digest() -> Digest;
    }
}
