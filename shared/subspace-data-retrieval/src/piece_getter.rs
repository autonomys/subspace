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
use subspace_core_primitives::{Piece, PieceIndex};

/// A type-erased error
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Object piece getter errors.
#[derive(Debug, thiserror::Error)]
pub enum PieceGetterError {
    /// Getting piece failed, a retry won't get the piece from this provider, try another provider
    #[error("Piece index {piece_index} can't be fetched by this provider")]
    NotFound { piece_index: PieceIndex },

    /// Getting piece failed, a retry won't get the piece from this provider, try another provider
    #[error("Piece index {piece_index} can't be fetched by this provider: {source:?}")]
    NotFoundWithError {
        piece_index: PieceIndex,
        source: BoxError,
    },

    /// Piece decoding error
    #[error("Piece data decoding error: {source:?}")]
    PieceDecoding {
        #[from]
        source: parity_scale_codec::Error,
    },
}

/// Trait representing a way to get pieces from the DSN for object reconstruction
#[async_trait]
pub trait ObjectPieceGetter: fmt::Debug {
    /// Get piece by index.
    ///
    /// Returns `Ok(None)` for temporary errors: the piece is not found, but immediately retrying
    /// this provider might return it.
    /// Returns `Err(_)` for permanent errors: this provider can't provide the piece at this time,
    /// and another provider should be attempted.
    async fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, BoxError>;
}

#[async_trait]
impl<T> ObjectPieceGetter for Arc<T>
where
    T: ObjectPieceGetter + Send + Sync + ?Sized,
{
    async fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, BoxError> {
        self.as_ref().get_piece(piece_index).await
    }
}

// Convenience methods, mainly used in testing
#[async_trait]
impl ObjectPieceGetter for NewArchivedSegment {
    async fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, BoxError> {
        if piece_index.segment_index() == self.segment_header.segment_index() {
            return Ok(Some(
                self.pieces
                    .pieces()
                    .nth(piece_index.position() as usize)
                    .expect("Piece position always exists in a segment; qed"),
            ));
        }

        Err(PieceGetterError::NotFound { piece_index }.into())
    }
}

#[async_trait]
impl ObjectPieceGetter for (PieceIndex, Piece) {
    async fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, BoxError> {
        if self.0 == piece_index {
            return Ok(Some(self.1.clone()));
        }

        Err(PieceGetterError::NotFound { piece_index }.into())
    }
}
