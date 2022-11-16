use crate::mock::{new_test_ext, DomainTracker, MockRuntime, StateRootsBound};
use crate::pallet::{CoreDomainsStateRoot, SystemDomainStateRoots};
use sp_domains::DomainId;
use sp_runtime::traits::{BlakeTwo256, Hash};

#[test]
fn test_update_state_root() {
    new_test_ext().execute_with(|| {
        let state_root = BlakeTwo256::hash_of(&1);
        assert!(DomainTracker::system_domain_state_roots().is_empty());

        DomainTracker::add_confirmed_system_domain_state_root(state_root);
        assert_eq!(
            DomainTracker::system_domain_state_roots(),
            vec![BlakeTwo256::hash_of(&1)]
        );
    })
}

#[test]
fn test_state_roots_bounded() {
    new_test_ext().execute_with(|| {
        SystemDomainStateRoots::<MockRuntime>::set(vec![
            BlakeTwo256::hash_of(&1),
            BlakeTwo256::hash_of(&2),
        ]);

        let state_root = BlakeTwo256::hash_of(&3);
        assert!(
            DomainTracker::system_domain_state_roots().len() == StateRootsBound::get() as usize
        );

        DomainTracker::add_confirmed_system_domain_state_root(state_root);
        assert_eq!(
            DomainTracker::system_domain_state_roots(),
            vec![BlakeTwo256::hash_of(&2), BlakeTwo256::hash_of(&3)]
        );
    })
}

#[test]
fn test_core_domain_state_roots_bounded() {
    new_test_ext().execute_with(|| {
        let domain_id = DomainId::new(101);
        CoreDomainsStateRoot::<MockRuntime>::insert(domain_id, 1, BlakeTwo256::hash_of(&1));
        CoreDomainsStateRoot::<MockRuntime>::insert(domain_id, 2, BlakeTwo256::hash_of(&2));

        assert!(DomainTracker::core_domains_state_root(domain_id, 1).is_some());
        DomainTracker::add_confirmed_core_domain_state_root(domain_id, 3, BlakeTwo256::hash_of(&3));
        assert!(DomainTracker::core_domains_state_root(domain_id, 1).is_none());
        assert!(DomainTracker::storage_key_for_core_domain_state_root(domain_id, 3).is_some());
        assert!(DomainTracker::storage_key_for_core_domain_state_root(domain_id, 1).is_none());
    })
}
