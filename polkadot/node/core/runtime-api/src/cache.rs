// Copyright 2020 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

use memory_lru::ResidentSize;
use parity_util_mem::{MallocSizeOf, MallocSizeOfExt};

use subspace_runtime_primitives::Hash;

struct ResidentSizeOf<T>(T);

impl<T: MallocSizeOf> ResidentSize for ResidentSizeOf<T> {
	fn resident_size(&self) -> usize {
		std::mem::size_of::<Self>() + self.0.malloc_size_of()
	}
}

struct DoesNotAllocate<T>(T);

impl<T> ResidentSize for DoesNotAllocate<T> {
	fn resident_size(&self) -> usize {
		std::mem::size_of::<Self>()
	}
}

// this is an ugly workaround for `AuthorityDiscoveryId`
// not implementing `MallocSizeOf`
struct VecOfDoesNotAllocate<T>(Vec<T>);

impl<T> ResidentSize for VecOfDoesNotAllocate<T> {
	fn resident_size(&self) -> usize {
		std::mem::size_of::<T>() * self.0.capacity()
	}
}

pub(crate) struct RequestResultCache;

impl Default for RequestResultCache {
	fn default() -> Self {
		Self
	}
}

pub(crate) enum RequestResult {
	SubmitCandidateReceipt(Hash, u32, Hash),
	SubmitTransactionBundle(Hash, Hash),
	PendingHead(Hash, Option<Hash>),
}
