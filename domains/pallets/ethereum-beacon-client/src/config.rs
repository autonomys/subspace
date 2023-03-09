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
    /// Index of current sync committee node in merkle tree of beacon state
    pub const CurrentSyncCommitteeIndex: u64 = 22;
    /// Depth of current sync committee node in merkle tree of beacon state
    pub const CurrentSyncCommitteeDepth: u64 = 5;
    /// Max elements of merkle proof branch
    pub const MaxProofBranchSize: u32 = 6;

    /// Depth of next sync committee node in merkle tree of beacon state
    pub const NextSyncCommitteeDepth: u64 = 5;
    /// Index of next sync committee node in merkle tree of beacon state
    pub const NextSyncCommitteeIndex: u64 = 23;

    /// Depth of finalized root node in merkle tree of beacon state
    pub const FinalizedRootDepth: u64 = 6;
    /// Index of finalized root node in merkle tree of beacon state
    pub const FinalizedRootIndex: u64 = 41;

    /// Max proposer slashings possible in beacon block body
    pub const MaxProposerSlashings: u32 = 16;
    /// Max attester slashings possible in beacon block body
    pub const MaxAttesterSlashings: u32 = 2;
    /// Max attestations possible in beacon block body
    pub const MaxAttestations: u32 = 128;
    /// Max deposits possible in beacon block body
    pub const MaxDeposits: u32 = 16;
    /// Max voluntary exists possible in beacon block body
    pub const MaxVoluntaryExits: u32 = 16;
    /// Max validators per committee possible for current network
    pub const MaxValidatorsPerCommittee: u32 = 2048;
    /// Max bytes of extra data possible in the execution payload
    pub const MaxExtraDataBytes: u32 = 32;
    /// Max bytes of log bloom possible in the execution payload
    pub const BytesPerLogsBloom: u32 = 256;
    /// Size of the fee recipient address (Ethereum address nominated by a
    /// beacon chain validator to receive tips from user transactions)
    pub const FeeRecipientSize: u32 = 20;

    /// Max depth of the deposit node in merkle tree which is used to verify
    /// validator deposits
    pub const DepositContractTreeDepth: u32 = 32;

    /// DomainType('0x07000000')
    /// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#domain-types
    pub const DomainSyncCommittee: [u8; 4] = [7, 0, 0, 0];

    pub const PublicKeySize: u32 = 48;
    pub const SignatureSize: u32 = 96;

    pub const GenesisSlot: u64 = 0;
}
