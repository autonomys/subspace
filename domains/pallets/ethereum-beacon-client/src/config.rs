use cfg_if::cfg_if;
use frame_support::parameter_types;

cfg_if! {
    if #[cfg(feature = "mainnet")] {
        mod mainnet;
        pub use mainnet::*;
    } else {
        mod goerli;
        pub use goerli::*;
    }
}

parameter_types! {
    pub const CurrentSyncCommitteeIndex: u64 = 22;
    pub const CurrentSyncCommitteeDepth: u64 = 5;
    pub const MaxProofBranchSize: u32 = 6;

    pub const NextSyncCommitteeDepth: u64 = 5;
    pub const NextSyncCommitteeIndex: u64 = 23;

    pub const FinalizedRootDepth: u64 = 6;
    pub const FinalizedRootIndex: u64 = 41;

    pub const MaxProposerSlashings: u32 = 16;
    pub const MaxAttesterSlashings: u32 = 2;
    pub const MaxAttestations: u32 = 128;
    pub const MaxDeposits: u32 = 16;
    pub const MaxVoluntaryExits: u32 = 16;
    pub const MaxValidatorsPerCommittee: u32 = 2048;
    pub const MaxExtraDataBytes: u32 = 32;
    pub const BytesPerLogsBloom: u32 = 256;
    pub const FeeRecipientSize: u32 = 20;

    pub const DepositContractTreeDepth: usize = 32;

    /// DomainType('0x07000000')
    /// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#domain-types
    pub const DomainSyncCommittee: [u8; 4] = [7, 0, 0, 0];

    pub const PublicKeySize: u32 = 48;
    pub const SignatureSize: u32 = 96;

    pub const GenesisSlot: u64 = 0;
}
