use subspace_archiving::pre_genesis_data;

#[test]
fn pre_genesis_data() {
    {
        // Below 1 Sha256 block
        let object = pre_genesis_data::from_seed(b"subspace", 10);
        assert_eq!(object.len(), 10);
        assert!(object.iter().find(|byte| **byte != 0).is_some());
    }
    {
        // Exactly 1 Sha256 block
        let object = pre_genesis_data::from_seed(b"subspace", 32);
        assert_eq!(object.len(), 32);
        assert!(object.iter().find(|byte| **byte != 0).is_some());
    }
    {
        // Over 1 Sha256 block
        let object = pre_genesis_data::from_seed(b"subspace", 40);
        assert_eq!(object.len(), 40);
        assert!(object.iter().find(|byte| **byte != 0).is_some());
    }
}
