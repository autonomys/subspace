//! Runtime registry for domains

use crate::pallet::{NextRuntimeId, RuntimeRegistry};
use crate::Config;
use codec::{Decode, Encode};
use frame_support::PalletError;
use scale_info::TypeInfo;
use sp_core::Hasher;
use sp_domains::{RuntimeId, RuntimeType};
use sp_std::vec::Vec;
use sp_version::RuntimeVersion;

/// Runtime specific errors
#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    FailedToExtractRuntimeVersion,
    InvalidSpecName,
    SpecVersionNeedsToIncrease,
    MaxRuntimeId,
    MissingRuntimeObject,
    MaxRuntimeUpgrades,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct RuntimeObject<Number, Hash> {
    pub runtime_name: Vec<u8>,
    pub runtime_type: RuntimeType,
    pub runtime_upgrades: u32,
    pub hash: Hash,
    pub code: Vec<u8>,
    pub version: RuntimeVersion,
    pub created_at: Number,
    pub updated_at: Number,
}

/// Extracts the runtime version of the provided code.
pub(crate) fn runtime_version(code: &[u8]) -> Result<RuntimeVersion, Error> {
    sp_io::misc::runtime_version(code)
        .and_then(|v| RuntimeVersion::decode(&mut &v[..]).ok())
        .ok_or(Error::FailedToExtractRuntimeVersion)
}

/// Upgrades current runtime with new runtime.
// TODO: we can use upstream's `can_set_code` after some adjustments
pub(crate) fn can_upgrade_code(
    current_version: &RuntimeVersion,
    update_code: &[u8],
) -> Result<RuntimeVersion, Error> {
    let new_version = runtime_version(update_code)?;

    if new_version.spec_name != current_version.spec_name {
        return Err(Error::InvalidSpecName);
    }

    if new_version.spec_version <= current_version.spec_version {
        return Err(Error::SpecVersionNeedsToIncrease);
    }

    Ok(new_version)
}

/// Registers a new domain runtime..
pub(crate) fn do_register_runtime<T: Config>(
    runtime_name: Vec<u8>,
    runtime_type: RuntimeType,
    code: Vec<u8>,
    at: T::BlockNumber,
) -> Result<RuntimeId, Error> {
    let runtime_version = runtime_version(&code)?;
    let runtime_hash = T::Hashing::hash(&code);
    let runtime_id = NextRuntimeId::<T>::get();

    RuntimeRegistry::<T>::insert(
        runtime_id,
        RuntimeObject {
            runtime_name,
            runtime_type,
            hash: runtime_hash,
            code,
            version: runtime_version,
            created_at: at,
            updated_at: at,
            runtime_upgrades: 0u32,
        },
    );

    let next_runtime_id = runtime_id.checked_add(1).ok_or(Error::MaxRuntimeId)?;
    NextRuntimeId::<T>::set(next_runtime_id);

    Ok(runtime_id)
}

// TODO: upgrade after a delay instead of immediately
pub(crate) fn do_upgrade_runtime<T: Config>(
    runtime_id: RuntimeId,
    code: Vec<u8>,
    at: T::BlockNumber,
) -> Result<(), Error> {
    RuntimeRegistry::<T>::try_mutate(runtime_id, |maybe_runtime_object| {
        let runtime_obj = maybe_runtime_object
            .as_mut()
            .ok_or(Error::MissingRuntimeObject)?;

        let new_runtime_version = can_upgrade_code(&runtime_obj.version, &code)?;
        let runtime_hash = T::Hashing::hash(&code);

        runtime_obj.code = code;
        runtime_obj.version = new_runtime_version;
        runtime_obj.hash = runtime_hash;
        runtime_obj.runtime_upgrades = runtime_obj
            .runtime_upgrades
            .checked_add(1)
            .ok_or(Error::MaxRuntimeUpgrades)?;
        runtime_obj.updated_at = at;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use crate::pallet::{NextRuntimeId, RuntimeRegistry};
    use crate::runtime_registry::{Error as RuntimeRegistryError, RuntimeObject};
    use crate::tests::{new_test_ext, Test};
    use crate::Error;
    use codec::Encode;
    use frame_support::assert_ok;
    use frame_support::dispatch::RawOrigin;
    use sp_domains::RuntimeType;
    use sp_runtime::DispatchError;
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
    fn create_domain_runtime() {
        let version = RuntimeVersion {
            spec_name: "test".into(),
            impl_name: Default::default(),
            authoring_version: 0,
            spec_version: 1,
            impl_version: 1,
            apis: Default::default(),
            transaction_version: 1,
            state_version: 0,
        };
        let read_runtime_version = ReadRuntimeVersion(version.encode());

        let mut ext = new_test_ext();
        ext.register_extension(sp_core::traits::ReadRuntimeVersionExt::new(
            read_runtime_version,
        ));
        ext.execute_with(|| {
            let res = crate::Pallet::<Test>::register_domain_runtime(
                RawOrigin::Root.into(),
                b"evm".to_vec(),
                RuntimeType::Evm,
                vec![1, 2, 3, 4],
            );

            assert_ok!(res);
            let runtime_obj = RuntimeRegistry::<Test>::get(0).unwrap();
            assert_eq!(runtime_obj.version, version);
            assert_eq!(NextRuntimeId::<Test>::get(), 1)
        })
    }

    #[test]
    fn upgrade_domain_runtime() {
        let mut ext = new_test_ext();
        ext.execute_with(|| {
            RuntimeRegistry::<Test>::insert(
                0,
                RuntimeObject {
                    runtime_name: b"evm".to_vec(),
                    runtime_type: Default::default(),
                    runtime_upgrades: 0,
                    hash: Default::default(),
                    code: vec![1, 2, 3, 4],
                    version: RuntimeVersion {
                        spec_name: "test".into(),
                        spec_version: 1,
                        impl_version: 1,
                        transaction_version: 1,
                        ..Default::default()
                    },
                    created_at: Default::default(),
                    updated_at: Default::default(),
                },
            );

            NextRuntimeId::<Test>::set(1);
        });

        let test_data = vec![
            (
                "test1",
                1,
                Err(Error::<Test>::RuntimeRegistry(
                    RuntimeRegistryError::InvalidSpecName,
                )),
            ),
            (
                "test",
                1,
                Err(Error::<Test>::RuntimeRegistry(
                    RuntimeRegistryError::SpecVersionNeedsToIncrease,
                )),
            ),
            ("test", 2, Ok(())),
        ];

        for (spec_name, spec_version, expected) in test_data.into_iter() {
            let version = RuntimeVersion {
                spec_name: spec_name.into(),
                spec_version,
                impl_version: 1,
                transaction_version: 1,
                ..Default::default()
            };
            let read_runtime_version = ReadRuntimeVersion(version.encode());
            ext.register_extension(sp_core::traits::ReadRuntimeVersionExt::new(
                read_runtime_version,
            ));

            ext.execute_with(|| {
                frame_system::Pallet::<Test>::set_block_number(100u64);
                let res = crate::Pallet::<Test>::upgrade_domain_runtime(
                    RawOrigin::Root.into(),
                    0,
                    vec![6, 7, 8, 9],
                );

                assert_eq!(res, expected.map_err(DispatchError::from))
            })
        }

        // verify upgrade
        ext.execute_with(|| {
            let runtime_obj = RuntimeRegistry::<Test>::get(0).unwrap();
            assert_eq!(
                runtime_obj.version,
                RuntimeVersion {
                    spec_name: "test".into(),
                    spec_version: 2,
                    impl_version: 1,
                    transaction_version: 1,
                    ..Default::default()
                }
            );
            assert_eq!(runtime_obj.runtime_upgrades, 1);
            assert_eq!(runtime_obj.code, vec![6, 7, 8, 9]);
            assert!(runtime_obj.updated_at > runtime_obj.created_at);
        })
    }
}
