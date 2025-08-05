mod v1_to_v5;
mod v5_to_v6;

pub(crate) use share_price_v0::OperatorEpochSharePrice as OperatorEpochSharePriceV0;
pub use v1_to_v5::VersionCheckedMigrateDomainsV1ToV5;
pub use v5_to_v6::VersionCheckedMigrateDomainsV5ToV6;

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
        use crate::staking::{SharePrice as SharePriceV1, get_share_price};
        use crate::tests::{Test, new_test_ext};

        #[test]
        fn test_share_price_structure_migration() {
            for share_price_v0 in [
                SharePrice(Perbill::from_parts(1)),
                SharePrice(Perbill::one()),
                SharePrice(Perbill::from_rational(123456789u32, 987654321u32)),
                SharePrice(Perbill::from_rational(
                    1_000_000_000u32,
                    1_000_000_000u32 + 123456u32,
                )),
            ] {
                let share_price_v1: SharePriceV1 = share_price_v0.clone().into();

                for n in [
                    1213u128,
                    940u128,
                    9678231u128,
                    2367u128,
                    834228u128,
                    298749827u128,
                    1234567890987654321u128,
                ] {
                    assert_eq!(
                        share_price_v0.0.mul_floor::<u128>(n),
                        share_price_v1.stake_to_shares::<Test>(n)
                    );

                    // The v1 share price `shares_to_stake` will return a strict rounding down result
                    // while the v0 may not, thus v0 share price may return more stake.
                    assert!(
                        share_price_v0.0.saturating_reciprocal_mul_floor::<u128>(n)
                            >= share_price_v1.shares_to_stake::<Test>(n)
                    );
                }
            }
        }

        #[test]
        fn test_share_price_getter_migration() {
            new_test_ext().execute_with(|| {
                let operator_id = 0;
                let domain_epoch = (0u32.into(), 0u32).into();
                let share_price_v0 = SharePrice(Perbill::from_rational(123456789u32, 987654321u32));
                let share_price_v1: SharePriceV1 = share_price_v0.clone().into();

                // Decode a v0 share price to v1 should result in an error
                let decode_result =
                    <SharePriceV1 as Decode>::decode(&mut share_price_v0.encode().as_slice());
                assert!(decode_result.is_err());

                // Insert an v0 share price
                OperatorEpochSharePrice::<Test>::insert(operator_id, domain_epoch, &share_price_v0);

                // `get_share_price` should internally convert the v0 share price to v1.
                let share_price = get_share_price::<Test>(operator_id, domain_epoch);

                assert_eq!(share_price, Some(share_price_v1));
            })
        }
    }
}
