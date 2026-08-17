use crate::pos_table::PosTableGenerator;

// New sectors get the abundance-backed table; sectors at or below the cutover keep the old one.
#[test]
fn dispatch_selects_by_cutover() {
    assert!(matches!(
        PosTableGenerator::new(true),
        PosTableGenerator::V2(_)
    ));
    assert!(matches!(
        PosTableGenerator::new(false),
        PosTableGenerator::V1(_)
    ));
    assert!(matches!(
        PosTableGenerator::default(),
        PosTableGenerator::V2(_)
    ));
}
