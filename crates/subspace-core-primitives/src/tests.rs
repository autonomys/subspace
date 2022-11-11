use crate::{BLS12_381_SCALAR_SAFE_BYTES, PIECE_SIZE, PLOT_SECTOR_SIZE, U256};
use num_integer::Roots;

#[test]
fn piece_distance_middle() {
    assert_eq!(U256::MIDDLE, U256::MAX / 2);
}

#[test]
fn piece_size_multiple_of_and_scalar() {
    assert_eq!(PIECE_SIZE % BLS12_381_SCALAR_SAFE_BYTES as usize, 0);
}

#[test]
fn sector_side_size_in_scalars_power_of_two() {
    let sector_size_in_scalars = PLOT_SECTOR_SIZE / u64::from(BLS12_381_SCALAR_SAFE_BYTES);
    let sector_side_size_in_scalars = sector_size_in_scalars.sqrt();

    assert!(sector_side_size_in_scalars.is_power_of_two());
}
