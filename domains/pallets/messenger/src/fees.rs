use crate::Config;
use codec::{Decode, Encode};
use frame_support::PalletId;
use scale_info::TypeInfo;
use sp_runtime::traits::AccountIdConversion;

/// Messenger Id used to store deposits and fees.
const MESSENGER_PALLET_ID: PalletId = PalletId(*b"messengr");

/// Returns the account_id to holds fees and and acts as treasury for messenger.
pub(crate) fn messenger_account_id<T: Config>() -> T::AccountId {
    MESSENGER_PALLET_ID.into_account_truncating()
}

/// Execution Fee to execute a send or receive request.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct ExecutionFee<Balance> {
    /// Fee paid to the relayer pool for the execution.
    pub relayer_pool_fee: Balance,
    /// Fee paid to the network for computation.
    pub compute_fee: Balance,
}

/// Fee model to send a request and receive a response from another domain.
/// A user of the endpoint will pay
///     - outbox_fee on src_domain
///     - inbox_fee on dst_domain
/// The reward is distributed to
///     - src_domain relayer pool when the response is received
///     - dst_domain relayer pool when the response acknowledgement from src_domain.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct FeeModel<Balance> {
    /// Fee paid by the endpoint user for any outgoing message.
    pub outbox_fee: ExecutionFee<Balance>,
    /// Fee paid by the endpoint user any incoming message.
    pub inbox_fee: ExecutionFee<Balance>,
}
