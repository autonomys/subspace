// Copyright (C) 2024 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Getting object pieces from the Subspace Distributed Storage Network, or various caches.

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;
use subspace_archiving::archiver::NewArchivedSegment;
use subspace_core_primitives::pieces::{Piece, PieceIndex};

/// Trait representing a way to get pieces from the DSN for object reconstruction
#[async_trait]
pub trait ObjectPieceGetter: fmt::Debug {
    /// Get piece by index.
    ///
    /// Returns `Ok(None)` if the piece is not found.
    /// Returns `Err(_)` if trying to get the piece caused an error.
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>>;
}

#[async_trait]
impl<T> ObjectPieceGetter for Arc<T>
where
    T: ObjectPieceGetter + Send + Sync + ?Sized,
{
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        self.as_ref().get_piece(piece_index).await
    }
}

// Convenience methods, mainly used in testing
#[async_trait]
impl ObjectPieceGetter for NewArchivedSegment {
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        if piece_index.segment_index() == self.segment_header.segment_index() {
            return Ok(Some(
                self.pieces
                    .pieces()
                    .nth(piece_index.position() as usize)
                    .expect("Piece position always exists in a segment; qed"),
            ));
        }

        Ok(None)
    }
}

#[async_trait]
impl ObjectPieceGetter for (PieceIndex, Piece) {
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        if self.0 == piece_index {
            return Ok(Some(self.1.clone()));
        }

        Ok(None)
    }
}
