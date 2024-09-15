use crate::farm::{FarmId, PieceCacheId};

#[test]
fn derive_sub_farm_ids_test() {
    let id = FarmId::new();
    let sub_ids = id.derive_sub_ids(128);
    assert_eq!(sub_ids.len(), 128);

    match id {
        FarmId::Ulid(id) => {
            let id: u128 = id.into();
            sub_ids.into_iter().zip(0..128u128).for_each(|(sub_id, i)| {
                let FarmId::Ulid(sub_id) = sub_id;
                let sub_id: u128 = sub_id.into();
                assert_eq!(sub_id, id + i);
            });
        }
    };
}

#[test]
fn derive_sub_cache_ids_test() {
    let id = PieceCacheId::new();
    let sub_ids = id.derive_sub_ids(128);
    assert_eq!(sub_ids.len(), 128);

    match id {
        PieceCacheId::Ulid(id) => {
            let id: u128 = id.into();
            sub_ids.into_iter().zip(0..128u128).for_each(|(sub_id, i)| {
                let PieceCacheId::Ulid(sub_id) = sub_id;
                let sub_id: u128 = sub_id.into();
                assert_eq!(sub_id, id + i);
            });
        }
    };
}
