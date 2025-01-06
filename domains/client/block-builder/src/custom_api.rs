//! Custom API that is efficient to collect storage roots.

// TODO: remove in later commits
#![allow(dead_code)]

use codec::{Codec, Decode, Encode};
use hash_db::{HashDB, Hasher, Prefix};
use sc_client_api::{backend, ExecutorProvider, StateBackend};
use sp_core::traits::{CallContext, CodeExecutor, RuntimeCode};
use sp_runtime::traits::{Block as BlockT, HashingFor, NumberFor};
use sp_runtime::{ApplyExtrinsicResult, ExtrinsicInclusionMode, TransactionOutcome};
use sp_state_machine::backend::AsTrieBackend;
use sp_state_machine::{
    BackendTransaction, DBValue, OverlayedChanges, StateMachine, StorageChanges, TrieBackend,
    TrieBackendBuilder, TrieBackendStorage,
};
use std::marker::PhantomData;
use std::sync::Arc;

type TrieBackendStorageFor<State, Block> =
    <State as StateBackend<HashingFor<Block>>>::TrieBackendStorage;

type TrieDeltaBackendFor<'a, State, Block> = TrieBackend<
    DeltaBackend<'a, TrieBackendStorageFor<State, Block>, HashingFor<Block>>,
    HashingFor<Block>,
>;

type TrieBackendFor<State, Block> =
    TrieBackend<TrieBackendStorageFor<State, Block>, HashingFor<Block>>;

/// Create a new trie backend with memory DB delta changes.
///
/// This can be used to verify any extrinsic-specific execution on the combined state of `backend`
/// and `delta`.
pub fn create_delta_backend<'a, S, H>(
    backend: &'a TrieBackend<S, H>,
    delta: BackendTransaction<H>,
    post_delta_root: H::Out,
) -> TrieBackend<DeltaBackend<'a, S, H>, H>
where
    S: 'a + TrieBackendStorage<H>,
    H: 'a + Hasher,
    H::Out: Codec,
{
    create_delta_backend_with_maybe_delta(backend, Some(delta), post_delta_root)
}

fn create_delta_backend_with_maybe_delta<'a, S, H>(
    backend: &'a TrieBackend<S, H>,
    maybe_delta: Option<BackendTransaction<H>>,
    post_delta_root: H::Out,
) -> TrieBackend<DeltaBackend<'a, S, H>, H>
where
    S: 'a + TrieBackendStorage<H>,
    H: 'a + Hasher,
    H::Out: Codec,
{
    let essence = backend.essence();
    let delta_backend = DeltaBackend {
        backend: essence.backend_storage(),
        delta: maybe_delta,
        _phantom: PhantomData::<H>,
    };
    TrieBackendBuilder::new(delta_backend, post_delta_root).build()
}

/// DeltaBackend provides the TrieBackend using main backend and some delta changes
/// that are not part of the main backend.
pub struct DeltaBackend<'a, S, H>
where
    S: 'a + TrieBackendStorage<H>,
    H: 'a + Hasher,
{
    backend: &'a S,
    delta: Option<BackendTransaction<H>>,
    _phantom: PhantomData<H>,
}

impl<'a, S, H> TrieBackendStorage<H> for DeltaBackend<'a, S, H>
where
    S: 'a + TrieBackendStorage<H>,
    H: 'a + Hasher,
{
    fn get(&self, key: &H::Out, prefix: Prefix) -> Result<Option<DBValue>, String> {
        if let Some(db) = &self.delta
            && let Some(v) = HashDB::get(db, key, prefix)
        {
            Ok(Some(v))
        } else {
            Ok(self.backend.get(key, prefix)?)
        }
    }
}

impl<'a, S, H> DeltaBackend<'a, S, H>
where
    S: 'a + TrieBackendStorage<H>,
    H: 'a + Hasher,
{
    fn consolidate_delta(&mut self, db: BackendTransaction<H>) {
        let delta = if let Some(mut delta) = self.delta.take() {
            delta.consolidate(db);
            delta
        } else {
            db
        };
        self.delta = Some(delta);
    }
}

pub(crate) struct TrieBackendApi<Client, Block: BlockT, Backend: backend::Backend<Block>, Exec> {
    parent_hash: Block::Hash,
    parent_number: NumberFor<Block>,
    client: Arc<Client>,
    state: Backend::State,
    executor: Exec,
    maybe_storage_changes: Option<StorageChanges<HashingFor<Block>>>,
}

impl<Client, Block, Backend, Exec> TrieBackendApi<Client, Block, Backend, Exec>
where
    Block: BlockT,
    Backend: backend::Backend<Block>,
    Client: ExecutorProvider<Block>,
    Exec: CodeExecutor,
{
    pub(crate) fn new(
        parent_hash: Block::Hash,
        parent_number: NumberFor<Block>,
        client: Arc<Client>,
        backend: Arc<Backend>,
        executor: Exec,
    ) -> Result<Self, sp_blockchain::Error> {
        let state = backend.state_at(parent_hash)?;
        Ok(Self {
            parent_hash,
            parent_number,
            client,
            state,
            executor,
            maybe_storage_changes: None,
        })
    }

    fn call_function<R: Decode>(
        &self,
        method: &str,
        call_data: Vec<u8>,
        trie_backend: &TrieDeltaBackendFor<Backend::State, Block>,
        runtime_code: RuntimeCode,
        overlayed_changes: &mut OverlayedChanges<HashingFor<Block>>,
    ) -> Result<R, sp_blockchain::Error> {
        let mut extensions = self
            .client
            .execution_extensions()
            .extensions(self.parent_hash, self.parent_number);

        let result = StateMachine::<_, _, _>::new(
            trie_backend,
            overlayed_changes,
            &self.executor,
            method,
            call_data.as_slice(),
            &mut extensions,
            &runtime_code,
            CallContext::Onchain,
        )
        .set_parent_hash(self.parent_hash)
        .execute()?;

        R::decode(&mut result.as_slice())
            .map_err(|err| sp_blockchain::Error::CallResultDecode("failed to decode Result", err))
    }

    fn consolidate_storage_changes(&mut self, mut changes: StorageChanges<HashingFor<Block>>) {
        let changes = if let Some(mut current_changes) = self.maybe_storage_changes.take() {
            current_changes
                .main_storage_changes
                .append(&mut changes.main_storage_changes);
            current_changes
                .child_storage_changes
                .append(&mut changes.child_storage_changes);
            current_changes
                .offchain_storage_changes
                .append(&mut changes.offchain_storage_changes);
            current_changes.transaction.consolidate(changes.transaction);
            current_changes.transaction_storage_root = changes.transaction_storage_root;
            current_changes
                .transaction_index_changes
                .append(&mut changes.transaction_index_changes);
            current_changes
        } else {
            changes
        };
        self.maybe_storage_changes = Some(changes)
    }

    pub(crate) fn initialize_block(
        &self,
        header: Block::Header,
        backend: &TrieDeltaBackendFor<Backend::State, Block>,
        runtime_code: RuntimeCode,
        overlayed_changes: &mut OverlayedChanges<HashingFor<Block>>,
    ) -> Result<ExtrinsicInclusionMode, sp_blockchain::Error> {
        let call_data = header.encode();
        self.call_function(
            "Core_initialize_block",
            call_data,
            backend,
            runtime_code,
            overlayed_changes,
        )
    }

    pub(crate) fn apply_extrinsic(
        &self,
        extrinsic: <Block as BlockT>::Extrinsic,
        backend: &TrieDeltaBackendFor<Backend::State, Block>,
        runtime_code: RuntimeCode,
        overlayed_changes: &mut OverlayedChanges<HashingFor<Block>>,
    ) -> Result<ApplyExtrinsicResult, sp_blockchain::Error> {
        let call_data = extrinsic.encode();
        self.call_function(
            "BlockBuilder_apply_extrinsic",
            call_data,
            backend,
            runtime_code,
            overlayed_changes,
        )
    }

    pub(crate) fn finalize_block(
        &self,
        backend: &TrieDeltaBackendFor<Backend::State, Block>,
        runtime_code: RuntimeCode,
        overlayed_changes: &mut OverlayedChanges<HashingFor<Block>>,
    ) -> Result<Block::Header, sp_blockchain::Error> {
        self.call_function(
            "BlockBuilder_finalize_block",
            vec![],
            backend,
            runtime_code,
            overlayed_changes,
        )
    }

    pub(crate) fn execute_in_transaction<F, R>(
        &mut self,
        call: F,
    ) -> Result<R, sp_blockchain::Error>
    where
        F: FnOnce(
            &Self,
            &TrieDeltaBackendFor<Backend::State, Block>,
            RuntimeCode,
            &mut OverlayedChanges<HashingFor<Block>>,
        ) -> TransactionOutcome<R>,
        R: Decode,
    {
        let trie_backend = self.state.as_trie_backend();
        let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
        let runtime_code = state_runtime_code
            .runtime_code()
            .map_err(sp_blockchain::Error::RuntimeCode)?;
        let mut overlayed_changes = OverlayedChanges::default();
        let (state_root, delta) = if let Some(changes) = &self.maybe_storage_changes {
            (
                changes.transaction_storage_root,
                Some(changes.transaction.clone()),
            )
        } else {
            (*trie_backend.root(), None)
        };
        let trie_delta_backend =
            create_delta_backend_with_maybe_delta(trie_backend, delta, state_root);

        let outcome = call(
            self,
            &trie_delta_backend,
            runtime_code,
            &mut overlayed_changes,
        );

        let result = match outcome {
            TransactionOutcome::Commit(result) => {
                let state_version = sp_core::storage::StateVersion::V1;
                let storage_changes = overlayed_changes
                    .drain_storage_changes(&trie_delta_backend, state_version)
                    .map_err(sp_blockchain::Error::StorageChanges)?;
                self.consolidate_storage_changes(storage_changes);
                result
            }
            TransactionOutcome::Rollback(result) => result,
        };

        Ok(result)
    }
}
