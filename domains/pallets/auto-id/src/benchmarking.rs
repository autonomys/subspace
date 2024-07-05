//! Benchmarking for `pallet-auto-id`.

use super::*;
use crate::Identifier;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(
    where T: pallet_timestamp::Config<Moment = u64>
)]
mod benchmarks {
    use super::*;

    fn do_register_issuer<T: Config>() {
        let account = account("issuer", 0, 0);
        let issuer_register_params = RegisterAutoId::decode(
            &mut include_bytes!("../res/benchmarks/issuer_register_auto_id_params").as_slice(),
        )
        .unwrap();
        Pallet::<T>::register_auto_id(RawOrigin::Signed(account).into(), issuer_register_params)
            .unwrap();
    }

    fn do_register_leaf<T: Config>() {
        let account = account("leaf", 0, 0);
        let leaf_register_params = RegisterAutoId::decode(
            &mut include_bytes!("../res/benchmarks/leaf_register_auto_id_params").as_slice(),
        )
        .unwrap();
        Pallet::<T>::register_auto_id(RawOrigin::Signed(account).into(), leaf_register_params)
            .unwrap();
    }

    #[benchmark]
    fn register_issuer_auto_id() {
        let issuer_register_params = RegisterAutoId::decode(
            &mut include_bytes!("../res/benchmarks/issuer_register_auto_id_params").as_slice(),
        )
        .unwrap();
        let account = account("issuer", 0, 0);
        pallet_timestamp::Pallet::<T>::set_timestamp(1_719_792_000_000u64);

        #[extrinsic_call]
        register_auto_id(RawOrigin::Signed(account), issuer_register_params);
    }

    #[benchmark]
    fn register_leaf_auto_id() {
        let account = account("leaf", 0, 0);
        pallet_timestamp::Pallet::<T>::set_timestamp(1_719_792_000_000u64);
        do_register_issuer::<T>();
        let leaf_register_params = RegisterAutoId::decode(
            &mut include_bytes!("../res/benchmarks/leaf_register_auto_id_params").as_slice(),
        )
        .unwrap();

        #[extrinsic_call]
        register_auto_id(RawOrigin::Signed(account), leaf_register_params);
    }

    #[benchmark]
    fn revoke_issuer_auto_id() {
        let account = account("issuer", 0, 0);
        pallet_timestamp::Pallet::<T>::set_timestamp(1_719_792_000_000u64);
        do_register_issuer::<T>();

        let issuer_id = Identifier::decode(
            &mut include_bytes!("../res/benchmarks/issuer_auto_id")
                .to_vec()
                .as_slice(),
        )
        .unwrap();

        let signature = Signature::decode(
            &mut include_bytes!("../res/benchmarks/issuer_auto_id_revocation_signature").as_slice(),
        )
        .unwrap();

        #[extrinsic_call]
        revoke_certificate(RawOrigin::Signed(account), issuer_id, signature);
    }

    #[benchmark]
    fn revoke_leaf_auto_id() {
        let account = account("leaf", 0, 0);
        pallet_timestamp::Pallet::<T>::set_timestamp(1_719_792_000_000u64);
        do_register_issuer::<T>();
        do_register_leaf::<T>();

        let leaf_id = Identifier::decode(
            &mut include_bytes!("../res/benchmarks/leaf_auto_id")
                .to_vec()
                .as_slice(),
        )
        .unwrap();

        let signature = Signature::decode(
            &mut include_bytes!("../res/benchmarks/leaf_auto_id_revocation_signature").as_slice(),
        )
        .unwrap();

        #[extrinsic_call]
        revoke_certificate(RawOrigin::Signed(account), leaf_id, signature);
    }

    #[benchmark]
    fn deactivate_auto_id() {
        let account = account("issuer", 0, 0);
        pallet_timestamp::Pallet::<T>::set_timestamp(1_719_792_000_000u64);
        do_register_issuer::<T>();

        let issuer_id = Identifier::decode(
            &mut include_bytes!("../res/benchmarks/issuer_auto_id")
                .to_vec()
                .as_slice(),
        )
        .unwrap();

        let signature = Signature::decode(
            &mut include_bytes!("../res/benchmarks/issuer_auto_id_deactivation_signature")
                .as_slice(),
        )
        .unwrap();

        #[extrinsic_call]
        deactivate_auto_id(RawOrigin::Signed(account), issuer_id, signature);
    }

    #[benchmark]
    fn renew_issuer_auto_id() {
        let account = account("issuer", 0, 0);
        pallet_timestamp::Pallet::<T>::set_timestamp(1_719_792_000_000u64);
        do_register_issuer::<T>();

        let issuer_id = Identifier::decode(
            &mut include_bytes!("../res/benchmarks/issuer_auto_id")
                .to_vec()
                .as_slice(),
        )
        .unwrap();

        let renew_auto_id = RenewAutoId::decode(
            &mut include_bytes!("../res/benchmarks/issuer_auto_id_renewal").as_slice(),
        )
        .unwrap();

        #[extrinsic_call]
        renew_auto_id(RawOrigin::Signed(account), issuer_id, renew_auto_id);
    }

    #[benchmark]
    fn renew_leaf_auto_id() {
        let account = account("leaf", 0, 0);
        pallet_timestamp::Pallet::<T>::set_timestamp(1_719_792_000_000u64);
        do_register_issuer::<T>();
        do_register_leaf::<T>();

        let leaf_id = Identifier::decode(
            &mut include_bytes!("../res/benchmarks/leaf_auto_id")
                .to_vec()
                .as_slice(),
        )
        .unwrap();

        let renew_auto_id = RenewAutoId::decode(
            &mut include_bytes!("../res/benchmarks/leaf_auto_id_renewal").as_slice(),
        )
        .unwrap();

        #[extrinsic_call]
        renew_auto_id(RawOrigin::Signed(account), leaf_id, renew_auto_id);
    }

    impl_benchmark_test_suite!(Pallet, tests::new_test_ext(), tests::Test,);
}
