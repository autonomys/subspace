//! `chiapos` utilities.

/// TODO: Workaround for "unconstrained generic constant" suggested in
///  https://github.com/rust-lang/rust/issues/82509#issuecomment-1165533546
#[derive(Debug)]
pub struct EvaluatableUsize<const N: usize>;
