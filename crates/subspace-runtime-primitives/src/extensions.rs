//! Extensions for Runtimes

use codec::{Decode, Encode};
use frame_support::pallet_prelude::{PhantomData, TypeInfo};
use frame_system::pallet_prelude::RuntimeCallFor;
use frame_system::Config;
use scale_info::prelude::fmt;
use sp_runtime::impl_tx_ext_default;
use sp_runtime::traits::{
    AsSystemOriginSigner, DispatchInfoOf, DispatchOriginOf, Dispatchable, Implication,
    TransactionExtension, ValidateResult,
};
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionSource, ValidTransaction};

/// Disable General Extrinsics until we migrate from Bare to General.
// TODO: Should either adapt or remove use of this extension during and after migration to
//  General Extrinsics from bare extrinsics
#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct DisableGeneralExtrinsics<Runtime>(PhantomData<Runtime>);

impl<Runtime> DisableGeneralExtrinsics<Runtime> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<Runtime> Default for DisableGeneralExtrinsics<Runtime> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Config> fmt::Debug for DisableGeneralExtrinsics<T> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DisableGeneralExtrinsics",)
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl<Runtime> TransactionExtension<RuntimeCallFor<Runtime>> for DisableGeneralExtrinsics<Runtime>
where
    Runtime: Config + scale_info::TypeInfo + fmt::Debug + Send + Sync,
    <RuntimeCallFor<Runtime> as Dispatchable>::RuntimeOrigin:
        AsSystemOriginSigner<<Runtime as Config>::AccountId> + Clone,
{
    const IDENTIFIER: &'static str = "DisableGeneralExtrinsics";
    type Implicit = ();
    type Val = ();
    type Pre = ();

    fn validate(
        &self,
        origin: DispatchOriginOf<RuntimeCallFor<Runtime>>,
        _call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl Implication,
        _source: TransactionSource,
    ) -> ValidateResult<Self::Val, RuntimeCallFor<Runtime>> {
        if origin.as_system_origin_signer().is_none() {
            Err(InvalidTransaction::Call.into())
        } else {
            Ok((ValidTransaction::default(), (), origin))
        }
    }

    impl_tx_ext_default!(RuntimeCallFor<Runtime>; weight);
    impl_tx_ext_default!(RuntimeCallFor<Runtime>; prepare);
}
