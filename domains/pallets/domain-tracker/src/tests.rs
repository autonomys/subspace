use crate::mock::{new_test_ext, DomainTracker, MockRuntime, RuntimeOrigin, StateRootsBound};
use crate::pallet::{CoreDomainsStateRoot, SystemDomainStateRoots};
use crate::Error;
use frame_support::{assert_err, assert_ok};
use sp_domain_tracker::InherentType;
use sp_domains::DomainId;
use sp_runtime::traits::{BlakeTwo256, Hash};

#[test]
fn test_update_state_root() {
    new_test_ext().execute_with(|| {
        let data = InherentType {
            system_domain_state_root: BlakeTwo256::hash_of(&1),
        };

        assert!(DomainTracker::system_domain_state_roots().is_empty());
        assert!(!DomainTracker::state_roots_updated());

        let res = DomainTracker::update_system_domain_state_root(
            RuntimeOrigin::none(),
            data.system_domain_state_root,
        );
        assert_ok!(res);
        assert_eq!(
            DomainTracker::system_domain_state_roots(),
            vec![BlakeTwo256::hash_of(&1)]
        );
        assert!(DomainTracker::state_roots_updated());

        // cannot update twice in same block
        let res = DomainTracker::update_system_domain_state_root(
            RuntimeOrigin::none(),
            data.system_domain_state_root,
        );
        assert_err!(res, Error::<MockRuntime>::StateRootsAlreadyUpdated)
    })
}

#[test]
fn test_state_roots_bounded() {
    new_test_ext().execute_with(|| {
        SystemDomainStateRoots::<MockRuntime>::set(vec![
            BlakeTwo256::hash_of(&1),
            BlakeTwo256::hash_of(&2),
        ]);

        let data = InherentType {
            system_domain_state_root: BlakeTwo256::hash_of(&3),
        };

        assert!(
            DomainTracker::system_domain_state_roots().len() == StateRootsBound::get() as usize
        );
        assert!(!DomainTracker::state_roots_updated());

        let res = DomainTracker::update_system_domain_state_root(
            RuntimeOrigin::none(),
            data.system_domain_state_root,
        );
        assert_ok!(res);
        assert_eq!(
            DomainTracker::system_domain_state_roots(),
            vec![BlakeTwo256::hash_of(&2), BlakeTwo256::hash_of(&3)]
        );
        assert!(DomainTracker::state_roots_updated());
    })
}

#[test]
fn test_core_domain_state_roots_bounded() {
    new_test_ext().execute_with(|| {
        let domain_id = DomainId::new(11);
        CoreDomainsStateRoot::<MockRuntime>::insert(domain_id, 1, BlakeTwo256::hash_of(&1));
        CoreDomainsStateRoot::<MockRuntime>::insert(domain_id, 2, BlakeTwo256::hash_of(&2));

        assert!(DomainTracker::core_domains_state_root(domain_id, 1).is_some());
        DomainTracker::add_confirmed_core_domain_state_root(domain_id, 3, BlakeTwo256::hash_of(&3));
        assert!(DomainTracker::core_domains_state_root(domain_id, 1).is_none());
        assert!(DomainTracker::storage_key_for_core_domain_state_root(domain_id, 3).is_some());
        assert!(DomainTracker::storage_key_for_core_domain_state_root(domain_id, 1).is_none());
    })
}
