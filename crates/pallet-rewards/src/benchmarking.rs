//! Benchmarking for `pallet-rewards`.

use frame_benchmarking::v2::*;

#[benchmarks]
mod benchmarks {
    #[cfg(not(feature = "std"))]
    extern crate alloc;

    use crate::pallet::{ProposerSubsidyPoints, VoterSubsidyPoints};
    use crate::{Call, Config, Pallet, RewardPoint};
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    use frame_system::RawOrigin;
    use sp_runtime::BoundedVec;

    #[benchmark]
    fn update_issuance_params(p: Linear<0, 20>, v: Linear<0, 20>) {
        #[extrinsic_call]
        _(
            RawOrigin::Root,
            BoundedVec::try_from(vec![RewardPoint::default(); p as usize]).unwrap(),
            BoundedVec::try_from(vec![RewardPoint::default(); v as usize]).unwrap(),
        );

        assert_eq!(ProposerSubsidyPoints::<T>::get().len(), p as usize);
        assert_eq!(VoterSubsidyPoints::<T>::get().len(), v as usize);
    }
}
