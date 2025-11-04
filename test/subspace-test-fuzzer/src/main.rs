use pallet_domains::fuzz::run_staking_fuzz;

fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        run_staking_fuzz(data);
    });
}
