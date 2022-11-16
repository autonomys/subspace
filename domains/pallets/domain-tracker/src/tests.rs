use crate::mock::{new_test_ext, DomainTracker};
use sp_domains::DomainId;
use sp_runtime::traits::{BlakeTwo256, Hash};

#[test]
fn test_update_state_root() {
    new_test_ext().execute_with(|| {
        let state_root = BlakeTwo256::hash_of(&1);
        assert!(DomainTracker::confirmed_domain_state_roots(DomainId::SYSTEM, 1).is_none());
        assert!(DomainTracker::unconfirmed_domain_state_roots(DomainId::SYSTEM, 1).is_none());

        DomainTracker::add_system_domain_state_root(1, state_root);
        assert!(DomainTracker::confirmed_domain_state_roots(DomainId::SYSTEM, 1).is_none());
        assert!(
            DomainTracker::unconfirmed_domain_state_roots(DomainId::SYSTEM, 1)
                == Some(BlakeTwo256::hash_of(&1))
        );
    })
}

#[test]
fn test_state_roots_bounded() {
    new_test_ext().execute_with(|| {
        for number in 0..=5u64 {
            DomainTracker::add_system_domain_state_root(number, BlakeTwo256::hash_of(&number));
        }

        // 0, 1 should be pruned
        for number in 0..=1 {
            assert!(
                DomainTracker::confirmed_domain_state_roots(DomainId::SYSTEM, number).is_none()
            );
            assert!(
                DomainTracker::unconfirmed_domain_state_roots(DomainId::SYSTEM, number).is_none()
            );
        }

        // 2, 3 should confirmed and not in unconfirmed
        for number in 2..=3 {
            assert!(
                DomainTracker::confirmed_domain_state_roots(DomainId::SYSTEM, number).is_some()
            );
            assert!(
                DomainTracker::unconfirmed_domain_state_roots(DomainId::SYSTEM, number).is_none()
            );
        }

        // 4, 5 should unconfirmed and not in confirmed
        for number in 4..=5 {
            assert!(
                DomainTracker::confirmed_domain_state_roots(DomainId::SYSTEM, number).is_none()
            );
            assert!(
                DomainTracker::unconfirmed_domain_state_roots(DomainId::SYSTEM, number).is_some()
            );
        }
    })
}

#[test]
fn test_state_roots_re_org() {
    new_test_ext().execute_with(|| {
        for number in 0..=5u64 {
            DomainTracker::add_system_domain_state_root(number, BlakeTwo256::hash_of(&number));
        }

        // let new latest be 4
        DomainTracker::add_system_domain_state_root(4, BlakeTwo256::hash_of(&4));

        // 0, 1 should be pruned
        for number in 0..=1 {
            assert!(
                DomainTracker::confirmed_domain_state_roots(DomainId::SYSTEM, number).is_none()
            );
            assert!(
                DomainTracker::unconfirmed_domain_state_roots(DomainId::SYSTEM, number).is_none()
            );
        }

        // 2, 3 should confirmed and not in unconfirmed
        for number in 2..=3 {
            assert!(
                DomainTracker::confirmed_domain_state_roots(DomainId::SYSTEM, number).is_some()
            );
            assert!(
                DomainTracker::unconfirmed_domain_state_roots(DomainId::SYSTEM, number).is_none()
            );
        }

        // 4 should unconfirmed and not in confirmed
        assert!(DomainTracker::confirmed_domain_state_roots(DomainId::SYSTEM, 4).is_none());
        assert!(DomainTracker::unconfirmed_domain_state_roots(DomainId::SYSTEM, 4).is_some());

        // 5 should be pruned as well
        assert!(DomainTracker::confirmed_domain_state_roots(DomainId::SYSTEM, 5).is_none());
        assert!(DomainTracker::unconfirmed_domain_state_roots(DomainId::SYSTEM, 5).is_none());
    })
}
