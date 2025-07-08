mod v1_to_v5;

pub(crate) use share_price_v0::OperatorEpochSharePrice as OperatorEpochSharePriceV0;
pub use v1_to_v5::VersionCheckedMigrateDomainsV1ToV5;

mod share_price_v0 {
    use crate::staking::{DomainEpoch, SharePrice as SharePriceV1};
    use crate::{Config, Pallet};
    use frame_support::pallet_prelude::OptionQuery;
    use frame_support::{Identity, storage_alias};
    use parity_scale_codec::{Decode, Encode};
    use scale_info::TypeInfo;
    use sp_domains::OperatorId;
    use sp_runtime::{Perbill, Perquintill};

    #[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Default)]
    pub struct SharePrice(Perbill);

    impl From<SharePrice> for SharePriceV1 {
        fn from(val: SharePrice) -> Self {
            SharePriceV1(Perquintill::from_parts(
                (val.0.deconstruct() as u64).saturating_mul(1_000_000_000u64),
            ))
        }
    }

    #[storage_alias]
    pub(crate) type OperatorEpochSharePrice<T: Config> = StorageDoubleMap<
        Pallet<T>,
        Identity,
        OperatorId,
        Identity,
        DomainEpoch,
        SharePrice,
        OptionQuery,
    >;

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::staking::SharePrice as SharePriceV1;
        use crate::tests::Test;

        #[test]
        fn test_share_price_structure_migration() {
            let share_price_v0 = SharePrice(Perbill::from_rational(123456789u32, 987654321u32));
            let share_price_v1: SharePriceV1 = share_price_v0.clone().into();

            for n in [
                1213u32,
                940u32,
                9678231u32,
                2367u32,
                834228u32,
                298749827u32,
            ] {
                assert_eq!(
                    share_price_v0.0.mul_floor(n) as u128,
                    share_price_v1.stake_to_shares::<Test>(n.into())
                );
                assert_eq!(
                    share_price_v0.0.saturating_reciprocal_mul_floor(n) as u128,
                    share_price_v1.shares_to_stake::<Test>(n.into())
                );
            }
        }
    }
}
