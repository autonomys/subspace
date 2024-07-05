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

    fn get_issuer_register_params() -> RegisterAutoId {
        let cert = include_bytes!("../res/benchmarks/issuer_tbs_certificate")
            .to_vec()
            .into();
        let signature_algorithm = include_bytes!("../res/benchmarks/issuer_signature_algorithm")
            .to_vec()
            .into();
        let signature = include_bytes!("../res/benchmarks/issuer_signature").to_vec();
        RegisterAutoId::X509(RegisterAutoIdX509::Root {
            certificate: cert,
            signature_algorithm,
            signature,
        })
    }

    fn get_leaf_register_params() -> RegisterAutoId {
        let cert = include_bytes!("../res/benchmarks/leaf_tbs_certificate")
            .to_vec()
            .into();
        let signature_algorithm = include_bytes!("../res/benchmarks/leaf_signature_algorithm")
            .to_vec()
            .into();
        let signature = include_bytes!("../res/benchmarks/leaf_signature").to_vec();
        let issuer_id = Identifier::decode(
            &mut include_bytes!("../res/benchmarks/issuer_auto_id")
                .to_vec()
                .as_slice(),
        )
        .unwrap();
        RegisterAutoId::X509(RegisterAutoIdX509::Leaf {
            issuer_id,
            certificate: cert,
            signature_algorithm,
            signature,
        })
    }

    fn do_register_issuer<T: Config>() {
        let account = account("issuer", 0, 0);
        let issuer_register_params = get_issuer_register_params();
        Pallet::<T>::register_auto_id(RawOrigin::Signed(account).into(), issuer_register_params)
            .unwrap()
    }

    fn do_register_leaf<T: Config>() {
        let account = account("leaf", 0, 0);
        let leaf_register_params = get_leaf_register_params();
        Pallet::<T>::register_auto_id(RawOrigin::Signed(account).into(), leaf_register_params)
            .unwrap()
    }

    #[benchmark]
    fn register_issuer_auto_id() {
        let issuer_register_params = get_issuer_register_params();
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
        let leaf_register_params = get_leaf_register_params();

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

    impl_benchmark_test_suite!(Pallet, tests::new_test_ext(), tests::Test,);
}
