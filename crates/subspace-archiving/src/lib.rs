//! Collection of modules used for dealing with archived state of Subspace Network.
#![cfg_attr(not(feature = "std"), no_std)]
#![feature(array_chunks, iter_collect_into)]

pub mod archiver;
pub mod piece_reconstructor;
pub mod reconstructor;
