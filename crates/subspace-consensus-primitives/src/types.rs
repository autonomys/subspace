use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use subspace_core_primitives::{Randomness, Salt, Sha256Hash};

/// Parameters for checking piece validity
pub struct PieceCheckParams {
    /// Records root of segment to which piece belongs
    pub records_root: Sha256Hash,
    /// Position of the piece in the segment
    pub position: u64,
    /// Record size, system parameter
    pub record_size: u32,
    /// Max plot size in pieces, system parameter
    pub max_plot_size: u64,
    /// Total number of pieces in the whole archival history
    pub total_pieces: u64,
}

/// Parameters for solution verification
pub struct VerifySolutionParams<'a> {
    /// Global randomness
    pub global_randomness: &'a Randomness,
    /// Solution range
    pub solution_range: u64,
    /// Salt
    pub salt: Salt,
    /// Parameters for checking piece validity.
    ///
    /// If `None`, piece validity check will be skipped.
    pub piece_check_params: Option<PieceCheckParams>,
}

/// Subspace global randomnesses used for deriving global challenges.
#[derive(Default, Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Copy, Debug, TypeInfo)]
pub struct GlobalRandomnesses {
    /// Global randomness used for deriving global challenge in current block/interval.
    pub current: Randomness,
    /// Global randomness that will be used for deriving global challenge in the next
    /// block/interval.
    pub next: Option<Randomness>,
}

/// Subspace solution ranges used for challenges.
#[derive(Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Copy, Debug, TypeInfo)]
pub struct SolutionRanges {
    /// Solution range in current block/era.
    pub current: u64,
    /// Solution range that will be used in the next block/era.
    pub next: Option<u64>,
    /// Voting solution range in current block/era.
    pub voting_current: u64,
    /// Voting solution range that will be used in the next block/era.
    pub voting_next: Option<u64>,
}

impl Default for SolutionRanges {
    fn default() -> Self {
        Self {
            current: u64::MAX,
            next: None,
            voting_current: u64::MAX,
            voting_next: None,
        }
    }
}

/// Subspace salts used for challenges.
#[derive(Default, Decode, Encode, MaxEncodedLen, PartialEq, Eq, Clone, Copy, Debug, TypeInfo)]
pub struct Salts {
    /// Salt used for challenges in current block/eon.
    pub current: Salt,
    /// Salt used for challenges after `salt` in the next eon.
    pub next: Option<Salt>,
    /// Whether salt should be updated in the next block (next salt is known upfront for some time
    /// and is not necessarily switching in the very next block).
    pub switch_next_block: bool,
}
