use crate::mock::{new_test_ext, Executive, RuntimeOrigin};
use frame_support::assert_ok;
use parity_scale_codec::Encode;
use sp_version::RuntimeVersion;

struct ReadRuntimeVersion(Vec<u8>);

impl sp_core::traits::ReadRuntimeVersion for ReadRuntimeVersion {
    fn read_runtime_version(
        &self,
        _wasm_code: &[u8],
        _ext: &mut dyn sp_externalities::Externalities,
    ) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }
}

#[test]
fn test_set_code() {
    let version = RuntimeVersion {
        spec_name: "".into(),
        impl_name: Default::default(),
        authoring_version: 0,
        spec_version: 1,
        impl_version: 1,
        apis: Default::default(),
        transaction_version: 1,
        system_version: 2,
    };
    let read_runtime_version = ReadRuntimeVersion(version.encode());

    let mut ext = new_test_ext();
    ext.register_extension(sp_core::traits::ReadRuntimeVersionExt::new(
        read_runtime_version,
    ));

    ext.execute_with(|| {
        let res = Executive::set_code(RuntimeOrigin::none(), vec![1, 2, 3, 4]);
        assert_ok!(res);
    })
}
