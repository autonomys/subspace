// Copyright (C) 2022 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Subspace fraud proof verification in the consensus level.

use codec::{Decode, Encode};
use sc_consensus::block_import::{BlockCheckParams, BlockImport, BlockImportParams, ImportResult};
use sp_api::{ProvideRuntimeApi, TransactionFor};
use sp_consensus::Error as ConsensusError;
use sp_domains::{DomainId, ExecutorApi};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_fraud_proof::VerifyFraudProof;

/// A block-import handler for Subspace fraud proof.
///
/// This scans each imported block for a fraud proof. If the extrinsc `pallet_domains::Call::submit_fraud_proof`
/// is found, ensure the included fraud proof in it is valid.
///
/// This block import object should be used with the subspace consensus block import together until
/// the fraud proof verification can be done in the runtime properly.
pub struct FraudProofBlockImport<Block, Client, I, Verifier, DomainHash> {
    inner: I,
    client: Arc<Client>,
    fraud_proof_verifier: Verifier,
    _phantom: PhantomData<(Block, DomainHash)>,
}

impl<Block, Client, I, Verifier, DomainHash> Clone
    for FraudProofBlockImport<Block, Client, I, Verifier, DomainHash>
where
    I: Clone,
    Verifier: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: self.client.clone(),
            fraud_proof_verifier: self.fraud_proof_verifier.clone(),
            _phantom: self._phantom,
        }
    }
}

#[async_trait::async_trait]
impl<Block, Client, Inner, Verifier, DomainHash> BlockImport<Block>
    for FraudProofBlockImport<Block, Client, Inner, Verifier, DomainHash>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + Send + Sync + 'static,
    Client::Api: ExecutorApi<Block, DomainHash>,
    Inner: BlockImport<Block, Transaction = TransactionFor<Client, Block>, Error = ConsensusError>
        + Send,
    Verifier: VerifyFraudProof<Block> + Send,
    DomainHash: Encode + Decode + Send,
{
    type Error = ConsensusError;
    type Transaction = TransactionFor<Client, Block>;

    async fn check_block(
        &mut self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.inner.check_block(block).await.map_err(Into::into)
    }

    async fn import_block(
        &mut self,
        block: BlockImportParams<Block, Self::Transaction>,
    ) -> Result<ImportResult, Self::Error> {
        let parent_hash = *block.header.parent_hash();

        if !block.state_action.skip_execution_checks() {
            if let Some(extrinsics) = &block.body {
                let fraud_proofs = self
                    .client
                    .runtime_api()
                    .extract_fraud_proofs(parent_hash, extrinsics.clone(), DomainId::SYSTEM)
                    .map_err(|e| ConsensusError::ClientImport(e.to_string()))?;

                for fraud_proof in fraud_proofs {
                    self.fraud_proof_verifier
                        .verify_fraud_proof(&fraud_proof)
                        .map_err(|e| ConsensusError::Other(Box::new(e)))?;
                }
            }
        }

        self.inner.import_block(block).await
    }
}

pub fn block_import<Block, Client, I, Verifier, DomainHash>(
    client: Arc<Client>,
    wrapped_block_import: I,
    fraud_proof_verifier: Verifier,
) -> FraudProofBlockImport<Block, Client, I, Verifier, DomainHash> {
    FraudProofBlockImport {
        inner: wrapped_block_import,
        client,
        fraud_proof_verifier,
        _phantom: PhantomData::<(Block, DomainHash)>,
    }
}
