//! Benchmarking for `pallet-executive`.

use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

#[cfg(test)]
use crate::Pallet as Executive;

fn get_runtime_code() -> Vec<u8> {
    include_bytes!("../res/evm_domain_test_runtime.compact.compressed.wasm").to_vec()
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn set_code() {
        let code = get_runtime_code();
        #[extrinsic_call]
        _(RawOrigin::None, code);
    }

    impl_benchmark_test_suite!(
        Executive,
        crate::mock::new_test_ext(),
        crate::mock::MockRuntime,
    );
}
