use codec::Encode;
use domain_runtime_primitives::{BlockNumber, Hash};
use parking_lot::{Mutex, RwLock};
use sc_client_api::{AuxStore, BlockBackend, HeaderBackend};
use sc_consensus_subspace::get_chain_constants;
use sp_api::{HeaderT, ProvideRuntimeApi};
use sp_blockchain::HeaderMetadata;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_domains::{DomainsApi, OpaqueBundle};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, NumberFor, Zero};
use std::collections::{HashSet, VecDeque};
use std::marker::PhantomData;
use std::sync::Arc;

/// `BundleCollector` collect all the bundle from the last K (confirm depth) blocks
/// of the best chain
struct BundleCollector<Block, Client> {
    client: Arc<Client>,
    confirm_depth_k: usize,
    _phantom_data: PhantomData<Block>,
}

impl<Block, Client> Clone for BundleCollector<Block, Client> {
    fn clone(&self) -> Self {
        BundleCollector {
            client: self.client.clone(),
            confirm_depth_k: self.confirm_depth_k,
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, Client> BundleCollector<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + ProvideRuntimeApi<Block>
        + AuxStore,
    Client::Api: DomainsApi<Block, BlockNumber, Hash> + SubspaceApi<Block, FarmerPublicKey>,
{
    fn new(client: Arc<Client>) -> Self {
        let confirm_depth_k = get_chain_constants(client.as_ref())
            .expect("Must always be able to get chain constants")
            .confirmation_depth_k() as usize;
        BundleCollector {
            client,
            confirm_depth_k,
            _phantom_data: PhantomData,
        }
    }

    fn successfully_submitted_bundles_at(
        &self,
        block_hash: Block::Hash,
        block_number: NumberFor<Block>,
    ) -> sp_blockchain::Result<HashSet<Hash>> {
        match self
            .client
            .runtime_api()
            .successful_bundle_hashes(block_hash)
        {
            Ok(bundle_hashes) => Ok(bundle_hashes.into_iter().collect()),
            Err(err) => {
                tracing::error!(
                    %err,
                    "Failed to calling runtime api bundles at block {block_hash:?}#{block_number:?}"
                );
                Err(err.into())
            }
        }
    }

    /// Initialize recent stored bundle from the last K block
    ///
    /// This function should only call when the recent stored bundle is not initialized.
    fn initialize_recent_stored_bundles(
        &self,
        mut hash: Block::Hash,
        bundle_stored_in_last_k: &mut VecDeque<BlockBundle<Block>>,
    ) -> sp_blockchain::Result<()> {
        assert!(
            bundle_stored_in_last_k.is_empty(),
            "recent stored bundle already initialized"
        );
        // `blocks` sorted from older block to newer block
        let mut blocks = VecDeque::new();
        for _ in 0..self.confirm_depth_k {
            match self.client.header(hash)? {
                Some(header) => {
                    blocks.push_front((hash, *header.number()));
                    if header.number().is_zero() {
                        break;
                    }
                    hash = *header.parent_hash()
                }
                _ => {
                    return Err(sp_blockchain::Error::Backend(format!(
                        "BlockHeader of {hash:?} unavailable"
                    )))
                }
            }
        }
        for (hash, number) in blocks {
            let bundles = self.successfully_submitted_bundles_at(hash, number)?;
            bundle_stored_in_last_k.push_front(BlockBundle::new(hash, number, bundles));
        }
        Ok(())
    }

    /// Collect bundles from the new blocks of the best chain, blocks are handled from
    /// older blcok to newer blcok, an `Err` may return in the middle and left some blocks
    /// unhandled, these blocks will be handled when processing the next new best block.
    fn on_new_best_block(
        &self,
        new_best_hash: Block::Hash,
        bundle_stored_in_last_k: &mut VecDeque<BlockBundle<Block>>,
    ) -> sp_blockchain::Result<()> {
        let current_best_hash =
            match BundleStoredInLastK::<Block>::best_hash(bundle_stored_in_last_k) {
                Some(h) => h,
                None => {
                    self.initialize_recent_stored_bundles(new_best_hash, bundle_stored_in_last_k)?;
                    return Ok(());
                }
            };

        let route = sp_blockchain::tree_route(&*self.client, current_best_hash, new_best_hash)?;
        let (retracted, enacted) = (route.retracted(), route.enacted());

        // Remove bundles from the stale fork
        for retracted_block in retracted {
            match bundle_stored_in_last_k.front() {
                Some(bb) if bb.block_hash == retracted_block.hash => {
                    bundle_stored_in_last_k.pop_front();
                }
                bb => {
                    return Err(sp_blockchain::Error::Application(Box::from(
                        format!(
                            "Got wrong block from the bundle-collector, expect {:?}, got {:?}, this should not happen",
                            retracted_block,
                            bb.map(|bb| bb.block_hash),
                        ),
                    )));
                }
            }
        }

        // Add bundles from the new block of the best fork, only need to process at most the last K
        // blocks as the result of other blocks will be dumpped immediately, this also help to prevent
        // the bundle validator from stuck on some pruned blocks because these blocks will be skip as
        // the chain grows.
        let needless_block = enacted.len().saturating_sub(self.confirm_depth_k);
        for enacted_block in enacted.iter().skip(needless_block) {
            let bundles =
                self.successfully_submitted_bundles_at(enacted_block.hash, enacted_block.number)?;
            bundle_stored_in_last_k.push_front(BlockBundle::new(
                enacted_block.hash,
                enacted_block.number,
                bundles,
            ));
        }

        // Remove blocks from the back end to keep at most the bundle of the last K blocks
        bundle_stored_in_last_k.truncate(self.confirm_depth_k);

        Ok(())
    }
}

#[derive(Clone)]
struct BlockBundle<Block: BlockT> {
    block_hash: Block::Hash,
    block_number: NumberFor<Block>,
    bundle_hashes: HashSet<Hash>,
}

impl<Block: BlockT> BlockBundle<Block> {
    fn new(
        block_hash: Block::Hash,
        block_number: NumberFor<Block>,
        bundle_hashes: HashSet<Hash>,
    ) -> Self {
        BlockBundle {
            block_hash,
            block_number,
            bundle_hashes,
        }
    }
}

/// `BundleStoredInLastK` maintains the last consecutive K blocks of the canonical chain and the bundles
/// stored within these blocks, it also used to share them between thread.
struct BundleStoredInLastK<Block: BlockT> {
    // Bundles stored in last K blocks, sorted from newer block to older block.
    bundles: Mutex<VecDeque<BlockBundle<Block>>>,
    // `bundle_syncer` used to sync `bundles` to other thread
    bundle_syncer: RwLock<VecDeque<BlockBundle<Block>>>,
}

impl<Block: BlockT> BundleStoredInLastK<Block> {
    fn new() -> Self {
        BundleStoredInLastK {
            bundles: Mutex::new(VecDeque::new()),
            bundle_syncer: RwLock::new(VecDeque::new()),
        }
    }

    fn best_hash(bundles: &VecDeque<BlockBundle<Block>>) -> Option<Block::Hash> {
        bundles.front().map(|bb| bb.block_hash)
    }

    // Update the recent stored bundles with the given closure, the `Mutex` of `bundles` will be held
    // while updating but there should only be one thread trying to update it. If the `Mutex` is already
    // be held an error will be returned instead of blocking.
    fn update_with<UpdateFn>(&self, update_fn: UpdateFn) -> sp_blockchain::Result<()>
    where
        UpdateFn: FnOnce(&mut VecDeque<BlockBundle<Block>>) -> sp_blockchain::Result<()>,
    {
        let mut bundles = match self.bundles.try_lock() {
            Some(b) => b,
            None => {
                return Err(sp_blockchain::Error::Application(Box::from(
                    "Failed to acquire bundles Mutex, this should not happen".to_owned(),
                )))
            }
        };
        let pre_best_hash = Self::best_hash(&bundles);
        let res = update_fn(&mut bundles);
        if pre_best_hash != Self::best_hash(&bundles) {
            *self.bundle_syncer.write() = bundles.clone();
        }
        res
    }

    fn contains_bundle(&self, hash: Hash) -> bool {
        let block_bundles = self.bundle_syncer.read();
        block_bundles
            .iter()
            .any(|bb| bb.bundle_hashes.contains(&hash))
    }

    // Get the canonical block hash by the given block number
    fn get_canonical_block_hash(&self, number: NumberFor<Block>) -> Option<Block::Hash> {
        let block_bundles = self.bundle_syncer.read();
        block_bundles
            .iter()
            .find(|b| b.block_number == number)
            .map(|b| b.block_hash)
    }
}

pub struct BundleValidator<Block: BlockT, Client> {
    bundle_collector: BundleCollector<Block, Client>,
    bundle_stored_in_last_k: Arc<BundleStoredInLastK<Block>>,
}

impl<Block: BlockT, Client> Clone for BundleValidator<Block, Client> {
    fn clone(&self) -> Self {
        BundleValidator {
            bundle_collector: self.bundle_collector.clone(),
            bundle_stored_in_last_k: self.bundle_stored_in_last_k.clone(),
        }
    }
}

impl<Block: BlockT, Client> BundleValidator<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + ProvideRuntimeApi<Block>
        + AuxStore,
    Client::Api: DomainsApi<Block, BlockNumber, Hash> + SubspaceApi<Block, FarmerPublicKey>,
{
    pub fn new(client: Arc<Client>) -> Self {
        BundleValidator {
            bundle_collector: BundleCollector::new(client),
            bundle_stored_in_last_k: Arc::new(BundleStoredInLastK::new()),
        }
    }

    pub fn update_recent_stored_bundles(
        &mut self,
        new_best_hash: Block::Hash,
        block_number: NumberFor<Block>,
    ) {
        if let Err(err) = self.bundle_stored_in_last_k.update_with(|bundles| {
            self.bundle_collector
                .on_new_best_block(new_best_hash, bundles)
        }) {
            tracing::error!(
                %err,
                ?new_best_hash,
                ?block_number,
                "Failed to update recent stored bundles for bundle-validator"
            );
        }
    }
}

#[derive(Debug)]
pub enum BundleError {
    DuplicatedBundle,
    ReceiptInFuture,
    ReceiptPointToUnknownBlock,
    BlockChain(sp_blockchain::Error),
}

impl From<sp_blockchain::Error> for BundleError {
    #[inline]
    fn from(err: sp_blockchain::Error) -> Self {
        BundleError::BlockChain(err)
    }
}

pub trait ValidateBundle<Block: BlockT, DomainNumber: Encode, DomainHash: Encode> {
    // For consensus chain, check the duplicated bundle and receipts.
    // For system domain, checks nothing.
    fn validate_bundle(
        &self,
        at: &BlockId<Block>,
        opaque_bundle: &OpaqueBundle<NumberFor<Block>, Block::Hash, DomainNumber, DomainHash>,
    ) -> Result<(), BundleError>;
}

impl<Block, DomainNumber, DomainHash, Client> ValidateBundle<Block, DomainNumber, DomainHash>
    for BundleValidator<Block, Client>
where
    Block: BlockT,
    DomainNumber: Encode,
    DomainHash: Encode,
    Client: HeaderBackend<Block>,
{
    fn validate_bundle(
        &self,
        at: &BlockId<Block>,
        opaque_bundle: &OpaqueBundle<NumberFor<Block>, Block::Hash, DomainNumber, DomainHash>,
    ) -> Result<(), BundleError> {
        // The hash used here must be the same as what is maintaining in `bundle_stored_in_last_k`,
        // namely the hash of `OpaqueBundle`
        let incoming_bundle = opaque_bundle.hash();
        // This implement will never return false negative result (i.e return `Err` for a new bundle)
        // but it may return false positive result (i.e return `Ok` for a duplicated bundle) if
        // `BundleCollector::on_new_best_block` return error and left some blocks unhandled, and it
        // will be recovered after successfully handling the next best block.
        if self
            .bundle_stored_in_last_k
            .contains_bundle(incoming_bundle)
        {
            return Err(BundleError::DuplicatedBundle);
        }

        let best_consensus_block_number = self
            .bundle_collector
            .client
            .block_number_from_id(at)?
            .ok_or(sp_blockchain::Error::Backend(format!(
                "Can not convert BlockId {at:?} to block number"
            )))?;
        if opaque_bundle.receipt.consensus_block_number > best_consensus_block_number {
            return Err(BundleError::ReceiptInFuture);
        }
        if let Some(expected_hash) = self
            .bundle_stored_in_last_k
            .get_canonical_block_hash(opaque_bundle.receipt.consensus_block_number)
        {
            if opaque_bundle.receipt.consensus_block_hash != expected_hash {
                return Err(BundleError::ReceiptPointToUnknownBlock);
            }
        }
        Ok(())
    }
}
