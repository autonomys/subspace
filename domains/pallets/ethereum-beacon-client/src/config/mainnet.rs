use frame_support::parameter_types;

parameter_types! {
    pub const SlotsPerEpoch: u64 = 32;
    pub const EpochsPerSyncCommitteePeriod: u64 = 256;
    pub const SyncCommitteeSize: u32 = 512;
}

#[cfg(any(test, feature = "runtime-benchmarks"))]
pub const IS_MAINNET: bool = true;
