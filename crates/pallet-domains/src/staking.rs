//! Staking for domains

use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_domains::{DomainId, EpochIndex, ExecutorPublicKey};
use sp_runtime::Percent;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::vec::Vec;

/// Type that represents an operator pool details.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct OperatorPool<Balance, NominatorId> {
    pub signing_key: ExecutorPublicKey,
    pub current_domain_id: DomainId,
    pub minimum_nominator_stake: Balance,
    pub nomination_tax: Percent,
    /// Total active stake for the current pool.
    pub current_total_stake: Balance,
    /// Total stake for the current pool in the next epoch.
    pub next_total_stake: Balance,
    /// Total shares of the nominators and the operator in this pool.
    pub total_shares: Balance,
    pub is_frozen: bool,
    /// Nominators under this operator pool.
    pub nominators: BTreeMap<NominatorId, Nominator<Balance>>,
    /// Pending transfers that will take effect in the next epoch.
    pub pending_transfers: Vec<PendingTransfer<NominatorId, Balance>>,
}

/// Type that represents an nominator details under a specific operator pool
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct Nominator<Balance> {
    pub shares: Balance,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Transfer<Balance> {
    Withdraw(Balance),
    Deposit(Balance),
}

/// Type that represents a pending transfer
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct PendingTransfer<NominatorId, Balance> {
    pub nominator_id: NominatorId,
    pub transfer: Transfer<Balance>,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct StakingSummary<OperatorId, Balance> {
    /// Current epoch index for the domain.
    pub current_epoch_index: EpochIndex,
    /// Total active stake for the current epoch.
    pub current_total_stake: Balance,
    /// Total stake for the next epoch.
    pub next_total_stake: Balance,
    /// Current operators for this epoch
    pub current_operators: Vec<OperatorId>,
    /// Operators for the next epoch.
    pub next_operators: Vec<OperatorId>,
}
