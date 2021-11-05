// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

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

//! PoC testsuite

use super::*;
use futures::executor::block_on;
use log::debug;
use parking_lot::Mutex;
use sc_block_builder::{BlockBuilder, BlockBuilderProvider};
use sc_client_api::{backend::TransactionFor, BlockchainEvents};
use sc_consensus::{BoxBlockImport, BoxJustificationImport};
use sc_consensus_slots::BackoffAuthoringOnFinalizedHeadLagging;
use sc_network::config::ProtocolConfig;
use sc_network_test::{
    BlockImportAdapter, Peer, PeersClient, PeersFullClient, TestClientBuilder,
    TestClientBuilderExt, TestNetFactory,
};
use sc_service::TaskManager;
use schnorrkel::Keypair;
use sp_consensus::{AlwaysCanAuthor, DisableProofRecording, NoNetwork as DummyOracle, Proposal};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::inherents::InherentDataProvider;
use sp_core::Public;
use sp_runtime::{
    generic::DigestItem,
    traits::{Block as BlockT, DigestFor},
};
use sp_timestamp::InherentDataProvider as TimestampInherentDataProvider;
// use std::sync::mpsc;
use rand::prelude::*;
use std::{cell::RefCell, task::Poll, time::Duration};
use subspace_core_primitives::Tag;
use subspace_solving::SubspaceCodec;
use substrate_test_runtime::{Block as TestBlock, Hash};
use subspace_core_primitives::Piece;

type Item = DigestItem<Hash>;

type Error = sp_blockchain::Error;

type TestClient = substrate_test_runtime_client::client::Client<
    substrate_test_runtime_client::Backend,
    substrate_test_runtime_client::ExecutorDispatch,
    TestBlock,
    substrate_test_runtime_client::runtime::RuntimeApi,
>;

#[derive(Copy, Clone, PartialEq)]
enum Stage {
    PreSeal,
    PostSeal,
}

type Mutator = Arc<dyn Fn(&mut TestHeader, Stage) + Send + Sync>;

type SubspaceBlockImport =
    PanickingBlockImport<crate::SubspaceBlockImport<TestBlock, TestClient, Arc<TestClient>>>;

#[derive(Clone)]
struct DummyFactory {
    client: Arc<TestClient>,
    epoch_changes: SharedEpochChanges<TestBlock, Epoch>,
    config: Config,
    mutator: Mutator,
}

struct DummyProposer {
    factory: DummyFactory,
    parent_hash: Hash,
    parent_number: u64,
    parent_slot: Slot,
}

impl Environment<TestBlock> for DummyFactory {
    type CreateProposer = future::Ready<Result<DummyProposer, Error>>;
    type Proposer = DummyProposer;
    type Error = Error;

    fn init(&mut self, parent_header: &<TestBlock as BlockT>::Header) -> Self::CreateProposer {
        let parent_slot = crate::find_pre_digest::<TestBlock>(parent_header)
            .expect("parent header has a pre-digest")
            .slot;

        future::ready(Ok(DummyProposer {
            factory: self.clone(),
            parent_hash: parent_header.hash(),
            parent_number: *parent_header.number(),
            parent_slot,
        }))
    }
}

impl DummyProposer {
    fn propose_with(
        &mut self,
        pre_digests: DigestFor<TestBlock>,
    ) -> future::Ready<
        Result<
            Proposal<
                TestBlock,
                sc_client_api::TransactionFor<substrate_test_runtime_client::Backend, TestBlock>,
                (),
            >,
            Error,
        >,
    > {
        let block_builder = self
            .factory
            .client
            .new_block_at(&BlockId::Hash(self.parent_hash), pre_digests, false)
            .unwrap();

        let mut block = match block_builder.build().map_err(|e| e.into()) {
            Ok(b) => b.block,
            Err(e) => return future::ready(Err(e)),
        };

        let this_slot = crate::find_pre_digest::<TestBlock>(block.header())
            .expect("baked block has valid pre-digest")
            .slot;

        // figure out if we should add a consensus digest, since the test runtime
        // doesn't.
        let epoch_changes = self.factory.epoch_changes.shared_data();
        let epoch = epoch_changes
            .epoch_data_for_child_of(
                descendent_query(&*self.factory.client),
                &self.parent_hash,
                self.parent_number,
                this_slot,
                |slot| Epoch::genesis(&self.factory.config, slot),
            )
            .expect("client has data to find epoch")
            .expect("can compute epoch for baked block");

        let first_in_epoch = self.parent_slot < epoch.start_slot;
        if first_in_epoch {
            // push a `Consensus` digest signalling next change.
            // we just reuse the same randomness as the prior
            // epoch. this will break when we add light client support, since
            // that will re-check the randomness logic off-chain.
            let digest_data = ConsensusLog::NextEpochData(NextEpochDescriptor {
                randomness: epoch.randomness.clone(),
            })
            .encode();
            let digest = DigestItem::Consensus(SUBSPACE_ENGINE_ID, digest_data);
            block.header.digest_mut().push(digest)
        }
        {
            let digest_data = ConsensusLog::SolutionRangeData(SolutionRangeDescriptor {
                solution_range: u64::MAX,
            })
            .encode();
            let digest = DigestItem::Consensus(SUBSPACE_ENGINE_ID, digest_data);
            block.header.digest_mut().push(digest)
        }
        {
            let digest_data = ConsensusLog::SaltData(SaltDescriptor { salt: 0 }).encode();
            let digest = DigestItem::Consensus(SUBSPACE_ENGINE_ID, digest_data);
            block.header.digest_mut().push(digest)
        }

        // mutate the block header according to the mutator.
        (self.factory.mutator)(&mut block.header, Stage::PreSeal);

        future::ready(Ok(Proposal {
            block,
            proof: (),
            storage_changes: Default::default(),
        }))
    }
}

impl Proposer<TestBlock> for DummyProposer {
    type Error = Error;
    type Transaction =
        sc_client_api::TransactionFor<substrate_test_runtime_client::Backend, TestBlock>;
    type Proposal = future::Ready<Result<Proposal<TestBlock, Self::Transaction, ()>, Error>>;
    type ProofRecording = DisableProofRecording;
    type Proof = ();

    fn propose(
        mut self,
        _: InherentData,
        pre_digests: DigestFor<TestBlock>,
        _: Duration,
        _: Option<usize>,
    ) -> Self::Proposal {
        self.propose_with(pre_digests)
    }
}

thread_local! {
    static MUTATOR: RefCell<Mutator> = RefCell::new(Arc::new(|_, _|()));
}

#[derive(Clone)]
pub struct PanickingBlockImport<B> {
    block_import: B,
    link: SubspaceLink<TestBlock>,
}

#[async_trait::async_trait]
impl<B: BlockImport<TestBlock>> BlockImport<TestBlock> for PanickingBlockImport<B>
where
    B::Transaction: Send,
    B: Send,
{
    type Error = B::Error;
    type Transaction = B::Transaction;

    async fn import_block(
        &mut self,
        block: BlockImportParams<TestBlock, Self::Transaction>,
        new_cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {
        // TODO: Here we are hacking around lack of transaction support in test runtime and
        //  remove known root blocks for current block to make sure block import doesn't fail, this
        //  should be removed once runtime supports transactions
        let block_number = block.header.number.into();
        let removed_root_blocks = self.link.root_blocks.lock().pop(&block_number);

        let import_result = self
            .block_import
            .import_block(block, new_cache)
            .await
            .expect("importing block failed");

        if let Some(removed_root_blocks) = removed_root_blocks {
            self.link
                .root_blocks
                .lock()
                .put(block_number, removed_root_blocks);
        }

        Ok(import_result)
    }

    async fn check_block(
        &mut self,
        block: BlockCheckParams<TestBlock>,
    ) -> Result<ImportResult, Self::Error> {
        Ok(self
            .block_import
            .check_block(block)
            .await
            .expect("checking block failed"))
    }
}

type SubspacePeer = Peer<Option<PeerData>, SubspaceBlockImport>;

pub struct SubspaceTestNet {
    peers: Vec<SubspacePeer>,
}

type TestHeader = <TestBlock as BlockT>::Header;

type TestSelectChain =
    substrate_test_runtime_client::LongestChain<substrate_test_runtime_client::Backend, TestBlock>;

pub struct TestVerifier {
    inner: SubspaceVerifier<
        TestBlock,
        PeersFullClient,
        TestSelectChain,
        AlwaysCanAuthor,
        Box<
            dyn CreateInherentDataProviders<
                TestBlock,
                (),
                InherentDataProviders = (TimestampInherentDataProvider, InherentDataProvider),
            >,
        >,
    >,
    mutator: Mutator,
}

#[async_trait::async_trait]
impl Verifier<TestBlock> for TestVerifier {
    /// Verify the given data and return the BlockImportParams and an optional
    /// new set of validators to import. If not, err with an Error-Message
    /// presented to the User in the logs.
    async fn verify(
        &mut self,
        mut block: BlockImportParams<TestBlock, ()>,
    ) -> Result<
        (
            BlockImportParams<TestBlock, ()>,
            Option<Vec<(CacheKeyId, Vec<u8>)>>,
        ),
        String,
    > {
        // apply post-sealing mutations (i.e. stripping seal, if desired).
        (self.mutator)(&mut block.header, Stage::PostSeal);
        self.inner.verify(block).await
    }
}

pub struct PeerData {
    link: SubspaceLink<TestBlock>,
    block_import: Mutex<
        Option<
            BoxBlockImport<
                TestBlock,
                TransactionFor<substrate_test_runtime_client::Backend, TestBlock>,
            >,
        >,
    >,
}

impl TestNetFactory for SubspaceTestNet {
    type Verifier = TestVerifier;
    type PeerData = Option<PeerData>;
    type BlockImport = SubspaceBlockImport;

    /// Create new test network with peers and given config.
    fn from_config(_config: &ProtocolConfig) -> Self {
        debug!(target: "subspace", "Creating test network from config");
        SubspaceTestNet { peers: Vec::new() }
    }

    fn make_block_import(
        &self,
        client: PeersClient,
    ) -> (
        BlockImportAdapter<Self::BlockImport>,
        Option<BoxJustificationImport<TestBlock>>,
        Option<PeerData>,
    ) {
        let client = client.as_full().expect("only full clients are tested");

        let config = Config::get_or_compute(&*client).expect("config available");
        let (block_import, link) =
            crate::block_import(false, config, client.clone(), client.clone())
                .expect("can initialize block-import");

        let block_import = PanickingBlockImport {
            block_import,
            link: link.clone(),
        };

        let data_block_import =
            Mutex::new(Some(Box::new(block_import.clone()) as BoxBlockImport<_, _>));
        (
            BlockImportAdapter::new(block_import),
            None,
            Some(PeerData {
                link,
                block_import: data_block_import,
            }),
        )
    }

    fn make_verifier(
        &self,
        client: PeersClient,
        _cfg: &ProtocolConfig,
        maybe_link: &Option<PeerData>,
    ) -> Self::Verifier {
        use substrate_test_runtime_client::DefaultTestClientBuilderExt;

        let client = client
            .as_full()
            .expect("only full clients are used in test");
        trace!(target: "subspace", "Creating a verifier");

        // ensure block import and verifier are linked correctly.
        let data = maybe_link
            .as_ref()
            .expect("Subspace link always provided to verifier instantiation");

        let (_, longest_chain) = TestClientBuilder::new().build_with_longest_chain();

        TestVerifier {
            inner: SubspaceVerifier {
                client: client.clone(),
                select_chain: longest_chain,
                create_inherent_data_providers: Box::new(|_, _| async {
                    let timestamp = TimestampInherentDataProvider::from_system_time();
                    let slot = InherentDataProvider::from_timestamp_and_duration(
                        *timestamp,
                        Duration::from_secs(6),
                    );

                    Ok((timestamp, slot))
                }),
                config: data.link.config.clone(),
                epoch_changes: data.link.epoch_changes.clone(),
                can_author_with: AlwaysCanAuthor,
                root_blocks: Arc::clone(&data.link.root_blocks),
                telemetry: None,
                signing_context: schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT),
            },
            mutator: MUTATOR.with(|m| m.borrow().clone()),
        }
    }

    fn peer(&mut self, i: usize) -> &mut SubspacePeer {
        trace!(target: "subspace", "Retrieving a peer");
        &mut self.peers[i]
    }

    fn peers(&self) -> &Vec<SubspacePeer> {
        trace!(target: "subspace", "Retrieving peers");
        &self.peers
    }

    fn mut_peers<F: FnOnce(&mut Vec<SubspacePeer>)>(&mut self, closure: F) {
        closure(&mut self.peers);
    }
}

#[test]
#[should_panic]
fn rejects_empty_block() {
    sp_tracing::try_init_simple();
    let mut net = SubspaceTestNet::new(3);
    let block_builder = |builder: BlockBuilder<_, _, _>| builder.build().unwrap().block;
    net.mut_peers(|peer| {
        peer[0].generate_blocks(1, BlockOrigin::NetworkInitialSync, block_builder);
    })
}

fn get_archived_pieces(client: &TestClient) -> Vec<Piece> {
    let genesis_block_id = BlockId::Number(Zero::zero());
    let runtime_api = client.runtime_api();

    let record_size = runtime_api.record_size(&genesis_block_id).unwrap();
    let recorded_history_segment_size = runtime_api
        .recorded_history_segment_size(&genesis_block_id)
        .unwrap();
    let pre_genesis_object_size = runtime_api
        .pre_genesis_object_size(&genesis_block_id)
        .unwrap();
    let pre_genesis_object_count = runtime_api
        .pre_genesis_object_count(&genesis_block_id)
        .unwrap();
    let pre_genesis_object_seed = runtime_api
        .pre_genesis_object_seed(&genesis_block_id)
        .unwrap();

    let mut object_archiver =
        ObjectArchiver::new(record_size as usize, recorded_history_segment_size as usize)
            .expect("Incorrect parameters for archiver");

    (0..pre_genesis_object_count)
        .map(|index| {
            object_archiver
                .add_object(pre_genesis_data::from_seed(
                    &pre_genesis_object_seed,
                    index,
                    pre_genesis_object_size,
                ))
                .into_iter()
        })
        .flatten()
        .map(|archived_segment| archived_segment.pieces.into_iter())
        .flatten()
        .collect()
}

fn run_one_test(mutator: impl Fn(&mut TestHeader, Stage) + Send + Sync + 'static) {
    sp_tracing::try_init_simple();
    let mutator = Arc::new(mutator) as Mutator;

    MUTATOR.with(|m| *m.borrow_mut() = mutator.clone());
    let net = SubspaceTestNet::new(3);

    let net = Arc::new(Mutex::new(net));
    let mut import_notifications = Vec::new();
    let mut subspace_futures = Vec::<Pin<Box<dyn Future<Output = ()>>>>::new();
    let tokio_runtime = sc_cli::build_runtime().unwrap();

    for peer_id in [0, 1, 2_usize].iter() {
        let mut net = net.lock();
        let peer = net.peer(*peer_id);
        let client = peer
            .client()
            .as_full()
            .expect("Only full clients are used in tests")
            .clone();
        let select_chain = peer.select_chain().expect("Full client has select_chain");

        let mut got_own = false;
        let mut got_other = false;

        let data = peer
            .data
            .as_ref()
            .expect("Subspace link set up during initialization");

        let environ = DummyFactory {
            client: client.clone(),
            config: data.link.config.clone(),
            epoch_changes: data.link.epoch_changes.clone(),
            mutator: mutator.clone(),
        };

        import_notifications.push(
            // run each future until we get one of our own blocks with number higher than 5
            // that was produced locally.
            client
                .import_notification_stream()
                .take_while(move |n| {
                    future::ready(
                        n.header.number() < &5 || {
                            if n.origin == BlockOrigin::Own {
                                got_own = true;
                            } else {
                                got_other = true;
                            }

                            // continue until we have at least one block of our own
                            // and one of another peer.
                            !(got_own && got_other)
                        },
                    )
                })
                .for_each(|_| future::ready(())),
        );

        let task_manager = TaskManager::new(tokio_runtime.handle().clone(), None).unwrap();

        super::start_subspace_archiver(&data.link, client.clone(), &task_manager.spawn_handle());

        let (archived_pieces_sender, archived_pieces_receiver) = oneshot::channel();

        std::thread::spawn({
            let client = Arc::clone(&client);

            move || {
                let archived_pieces = get_archived_pieces(&client);
                archived_pieces_sender.send(archived_pieces).unwrap();
            }
        });

        let subspace_worker = start_subspace(SubspaceParams {
            block_import: data
                .block_import
                .lock()
                .take()
                .expect("import set up during init"),
            select_chain,
            client,
            env: environ,
            sync_oracle: DummyOracle,
            create_inherent_data_providers: Box::new(|_, _| async {
                let timestamp = TimestampInherentDataProvider::from_system_time();
                let slot = InherentDataProvider::from_timestamp_and_duration(
                    *timestamp,
                    Duration::from_secs(6),
                );

                Ok((timestamp, slot))
            }),
            force_authoring: false,
            backoff_authoring_blocks: Some(BackoffAuthoringOnFinalizedHeadLagging::default()),
            subspace_link: data.link.clone(),
            can_author_with: sp_consensus::AlwaysCanAuthor,
            justification_sync_link: (),
            block_proposal_slot_portion: SlotProportion::new(0.5),
            max_block_proposal_slot_portion: None,
            telemetry: None,
        })
        .expect("Starts Subspace");

        let mut new_slot_notification_stream = data.link.new_slot_notification_stream().subscribe();
        let subspace_farmer = async move {
            let keypair = Keypair::generate();
            let subspace_solving = SubspaceCodec::new(&keypair.public);
            let ctx = schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT);
            let (piece_index, mut piece) = archived_pieces_receiver
                .await
                .unwrap()
                .into_iter()
                .enumerate()
                .choose(&mut rand::thread_rng())
                .map(|(piece_index, piece)| (piece_index as u64, piece))
                .unwrap();
            subspace_solving.encode(piece_index, &mut piece).unwrap();

            while let Some(NewSlotNotification {
                new_slot_info,
                mut solution_sender,
            }) = new_slot_notification_stream.next().await
            {
                if Into::<u64>::into(new_slot_info.slot) % 3 == (*peer_id) as u64 {
                    let tag: Tag = subspace_solving::create_tag(&piece, new_slot_info.salt);

                    let _ = solution_sender
                        .send((
                            Solution {
                                public_key: FarmerPublicKey::from_slice(&keypair.public.to_bytes()),
                                piece_index,
                                encoding: piece.to_vec(),
                                signature: keypair.sign(ctx.bytes(&tag)).to_bytes().to_vec(),
                                tag,
                            },
                            keypair.secret.to_bytes().into(),
                        ))
                        .await;
                }
            }
        };

        subspace_futures.push(Box::pin(subspace_worker));
        subspace_futures.push(Box::pin(subspace_farmer));
    }
    tokio_runtime.block_on(future::select(
        futures::future::poll_fn(move |cx| {
            let mut net = net.lock();
            net.poll(cx);
            for p in net.peers() {
                for (h, e) in p.failed_verifications() {
                    panic!("Verification failed for {:?}: {}", h, e);
                }
            }

            Poll::<()>::Pending
        }),
        future::select(
            future::join_all(import_notifications),
            future::join_all(subspace_futures),
        ),
    ));
}

// TODO: Un-ignore once `submit_test_store_root_block()` is working or transactions are supported in
//  test runtime
#[test]
#[ignore]
fn authoring_blocks() {
    run_one_test(|_, _| ())
}

#[test]
#[should_panic]
fn rejects_missing_inherent_digest() {
    run_one_test(|header: &mut TestHeader, stage| {
        let v = std::mem::take(&mut header.digest_mut().logs);
        header.digest_mut().logs = v
            .into_iter()
            .filter(|v| stage == Stage::PostSeal || v.as_subspace_pre_digest().is_none())
            .collect()
    })
}

#[test]
#[should_panic]
fn rejects_missing_seals() {
    run_one_test(|header: &mut TestHeader, stage| {
        let v = std::mem::take(&mut header.digest_mut().logs);
        header.digest_mut().logs = v
            .into_iter()
            .filter(|v| stage == Stage::PreSeal || v.as_subspace_seal().is_none())
            .collect()
    })
}

#[test]
#[should_panic]
fn rejects_missing_consensus_digests() {
    run_one_test(|header: &mut TestHeader, stage| {
        let v = std::mem::take(&mut header.digest_mut().logs);
        header.digest_mut().logs = v
            .into_iter()
            .filter(|v| stage == Stage::PostSeal || v.as_next_epoch_descriptor().is_none())
            .collect()
    });
}

#[test]
fn wrong_consensus_engine_id_rejected() {
    sp_tracing::try_init_simple();
    let keypair = Keypair::generate();
    let ctx = schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT);
    let bad_seal: Item = DigestItem::Seal([0; 4], keypair.sign(ctx.bytes(b"")).to_bytes().to_vec());
    assert!(bad_seal.as_subspace_pre_digest().is_none());
    assert!(bad_seal.as_subspace_seal().is_none())
}

#[test]
fn malformed_pre_digest_rejected() {
    sp_tracing::try_init_simple();
    let bad_seal: Item = DigestItem::Seal(SUBSPACE_ENGINE_ID, [0; 64].to_vec());
    assert!(bad_seal.as_subspace_pre_digest().is_none());
}

#[test]
fn sig_is_not_pre_digest() {
    sp_tracing::try_init_simple();
    let keypair = Keypair::generate();
    let ctx = schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT);
    let bad_seal: Item = DigestItem::Seal(
        SUBSPACE_ENGINE_ID,
        keypair.sign(ctx.bytes(b"")).to_bytes().to_vec(),
    );
    assert!(bad_seal.as_subspace_pre_digest().is_none());
    assert!(bad_seal.as_subspace_seal().is_some())
}

/// Claims the given slot number. always returning a dummy block.
pub fn dummy_claim_slot(slot: Slot, _epoch: &Epoch) -> Option<(PreDigest, FarmerPublicKey)> {
    return Some((
        PreDigest {
            solution: Solution {
                public_key: Default::default(),
                piece_index: 0,
                encoding: vec![],
                signature: vec![],
                tag: Default::default(),
            },
            slot,
        },
        FarmerPublicKey::default(),
    ));
}

#[test]
fn can_author_block() {
    sp_tracing::try_init_simple();

    let mut i = 0;
    let epoch = Epoch {
        start_slot: 0.into(),
        randomness: [0; 32],
        epoch_index: 1,
        duration: 100,
        config: SubspaceEpochConfiguration { c: (3, 10) },
    };

    let mut _config = crate::SubspaceGenesisConfiguration {
        slot_duration: 1000,
        epoch_length: 100,
        c: (3, 10),
        randomness: [0; 32],
    };

    // we might need to try a couple of times
    loop {
        match dummy_claim_slot(i.into(), &epoch) {
            None => i += 1,
            Some(s) => {
                debug!(target: "subspace", "Authored block {:?}", s.0);
                break;
            }
        }
    }
}

// Propose and import a new Subspace block on top of the given parent.
fn propose_and_import_block<Transaction: Send + 'static>(
    parent: &TestHeader,
    slot: Option<Slot>,
    proposer_factory: &mut DummyFactory,
    block_import: &mut BoxBlockImport<TestBlock, Transaction>,
) -> sp_core::H256 {
    let mut proposer = futures::executor::block_on(proposer_factory.init(parent)).unwrap();

    let slot = slot.unwrap_or_else(|| {
        let parent_pre_digest = find_pre_digest::<TestBlock>(parent).unwrap();
        parent_pre_digest.slot + 1
    });

    let keypair = Keypair::generate();
    let ctx = schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT);

    let (pre_digest, signature) = {
        let encoding = Piece::default();
        let tag: Tag = [0u8; 8];

        let signature = keypair.sign(ctx.bytes(&tag)).to_bytes().to_vec();

        (
            sp_runtime::generic::Digest {
                logs: vec![Item::subspace_pre_digest(PreDigest {
                    slot,
                    solution: Solution {
                        public_key: FarmerPublicKey::from_slice(&keypair.public.to_bytes()),
                        piece_index: 0,
                        encoding: encoding.to_vec(),
                        signature: signature.clone(),
                        tag,
                    },
                })],
            },
            signature,
        )
    };

    let parent_hash = parent.hash();

    let mut block = futures::executor::block_on(proposer.propose_with(pre_digest))
        .unwrap()
        .block;

    let epoch_descriptor = proposer_factory
        .epoch_changes
        .shared_data()
        .epoch_descriptor_for_child_of(
            descendent_query(&*proposer_factory.client),
            &parent_hash,
            *parent.number(),
            slot,
        )
        .unwrap()
        .unwrap();

    let seal = Item::subspace_seal(signature.try_into().unwrap());

    let post_hash = {
        block.header.digest_mut().push(seal.clone());
        let h = block.header.hash();
        block.header.digest_mut().pop();
        h
    };

    let mut import = BlockImportParams::new(BlockOrigin::Own, block.header);
    import.post_digests.push(seal);
    import.body = Some(block.extrinsics);
    import.intermediates.insert(
        Cow::from(INTERMEDIATE_KEY),
        Box::new(SubspaceIntermediate::<TestBlock> { epoch_descriptor }) as Box<_>,
    );
    import.fork_choice = Some(ForkChoiceStrategy::LongestChain);
    let import_result = block_on(block_import.import_block(import, Default::default())).unwrap();

    match import_result {
        ImportResult::Imported(_) => {}
        _ => panic!("expected block to be imported"),
    }

    post_hash
}

#[test]
fn importing_block_one_sets_genesis_epoch() {
    let mut net = SubspaceTestNet::new(1);

    let peer = net.peer(0);
    let data = peer
        .data
        .as_ref()
        .expect("Subspace link set up during initialization");
    let client = peer
        .client()
        .as_full()
        .expect("Only full clients are used in tests")
        .clone();

    let mut proposer_factory = DummyFactory {
        client: client.clone(),
        config: data.link.config.clone(),
        epoch_changes: data.link.epoch_changes.clone(),
        mutator: Arc::new(|_, _| ()),
    };

    let mut block_import = data
        .block_import
        .lock()
        .take()
        .expect("import set up during init");

    let genesis_header = client.header(&BlockId::Number(0)).unwrap().unwrap();

    let block_hash = propose_and_import_block(
        &genesis_header,
        Some(999.into()),
        &mut proposer_factory,
        &mut block_import,
    );

    let genesis_epoch = Epoch::genesis(&data.link.config, 999.into());

    let epoch_changes = data.link.epoch_changes.shared_data();
    let epoch_for_second_block = epoch_changes
        .epoch_data_for_child_of(
            descendent_query(&*client),
            &block_hash,
            1,
            1000.into(),
            |slot| Epoch::genesis(&data.link.config, slot),
        )
        .unwrap()
        .unwrap();

    assert_eq!(epoch_for_second_block, genesis_epoch);
}

#[test]
fn importing_epoch_change_block_prunes_tree() {
    use sc_client_api::Finalizer;

    let mut net = SubspaceTestNet::new(1);

    let peer = net.peer(0);
    let data = peer
        .data
        .as_ref()
        .expect("Subspace link set up during initialization");

    let client = peer
        .client()
        .as_full()
        .expect("Only full clients are used in tests")
        .clone();
    let mut block_import = data
        .block_import
        .lock()
        .take()
        .expect("import set up during init");
    let epoch_changes = data.link.epoch_changes.clone();

    let mut proposer_factory = DummyFactory {
        client: client.clone(),
        config: data.link.config.clone(),
        epoch_changes: data.link.epoch_changes.clone(),
        mutator: Arc::new(|_, _| ()),
    };

    // This is just boilerplate code for proposing and importing n valid Subspace
    // blocks that are built on top of the given parent. The proposer takes care
    // of producing epoch change digests according to the epoch duration (which
    // is set to 6 slots in the test runtime).
    let mut propose_and_import_blocks = |parent_id, n| {
        let mut hashes = Vec::new();
        let mut parent_header = client.header(&parent_id).unwrap().unwrap();

        for _ in 0..n {
            let block_hash = propose_and_import_block(
                &parent_header,
                None,
                &mut proposer_factory,
                &mut block_import,
            );
            hashes.push(block_hash);
            parent_header = client.header(&BlockId::Hash(block_hash)).unwrap().unwrap();
        }

        hashes
    };

    // This is the block tree that we're going to use in this test. Each node
    // represents an epoch change block, the epoch duration is 6 slots.
    //
    //    *---- F (#7)
    //   /                 *------ G (#19) - H (#25)
    //  /                 /
    // A (#1) - B (#7) - C (#13) - D (#19) - E (#25)
    //                              \
    //                               *------ I (#25)

    // Create and import the canon chain and keep track of fork blocks (A, C, D)
    // from the diagram above.
    let canon_hashes = propose_and_import_blocks(BlockId::Number(0), 30);

    // Create the forks
    let fork_1 = propose_and_import_blocks(BlockId::Hash(canon_hashes[0]), 10);
    let fork_2 = propose_and_import_blocks(BlockId::Hash(canon_hashes[12]), 15);
    let fork_3 = propose_and_import_blocks(BlockId::Hash(canon_hashes[18]), 10);

    // We should be tracking a total of 9 epochs in the fork tree
    assert_eq!(epoch_changes.shared_data().tree().iter().count(), 9,);

    // And only one root
    assert_eq!(epoch_changes.shared_data().tree().roots().count(), 1,);

    // We finalize block #13 from the canon chain, so on the next epoch
    // change the tree should be pruned, to not contain F (#7).
    client
        .finalize_block(BlockId::Hash(canon_hashes[12]), None, false)
        .unwrap();
    propose_and_import_blocks(BlockId::Hash(client.chain_info().best_hash), 7);

    // at this point no hashes from the first fork must exist on the tree
    assert!(!epoch_changes
        .shared_data()
        .tree()
        .iter()
        .map(|(h, _, _)| h)
        .any(|h| fork_1.contains(h)),);

    // but the epoch changes from the other forks must still exist
    assert!(epoch_changes
        .shared_data()
        .tree()
        .iter()
        .map(|(h, _, _)| h)
        .any(|h| fork_2.contains(h)));

    assert!(epoch_changes
        .shared_data()
        .tree()
        .iter()
        .map(|(h, _, _)| h)
        .any(|h| fork_3.contains(h)),);

    // finalizing block #25 from the canon chain should prune out the second fork
    client
        .finalize_block(BlockId::Hash(canon_hashes[24]), None, false)
        .unwrap();
    propose_and_import_blocks(BlockId::Hash(client.chain_info().best_hash), 8);

    // at this point no hashes from the second fork must exist on the tree
    assert!(!epoch_changes
        .shared_data()
        .tree()
        .iter()
        .map(|(h, _, _)| h)
        .any(|h| fork_2.contains(h)),);

    // while epoch changes from the last fork should still exist
    assert!(epoch_changes
        .shared_data()
        .tree()
        .iter()
        .map(|(h, _, _)| h)
        .any(|h| fork_3.contains(h)),);
}

#[test]
#[should_panic]
fn verify_slots_are_strictly_increasing() {
    let mut net = SubspaceTestNet::new(1);

    let peer = net.peer(0);
    let data = peer
        .data
        .as_ref()
        .expect("Subspace link set up during initialization");

    let client = peer
        .client()
        .as_full()
        .expect("Only full clients are used in tests")
        .clone();
    let mut block_import = data
        .block_import
        .lock()
        .take()
        .expect("import set up during init");

    let mut proposer_factory = DummyFactory {
        client: client.clone(),
        config: data.link.config.clone(),
        epoch_changes: data.link.epoch_changes.clone(),
        mutator: Arc::new(|_, _| ()),
    };

    let genesis_header = client.header(&BlockId::Number(0)).unwrap().unwrap();

    // we should have no issue importing this block
    let b1 = propose_and_import_block(
        &genesis_header,
        Some(999.into()),
        &mut proposer_factory,
        &mut block_import,
    );

    let b1 = client.header(&BlockId::Hash(b1)).unwrap().unwrap();

    // we should fail to import this block since the slot number didn't increase.
    // we will panic due to the `PanickingBlockImport` defined above.
    propose_and_import_block(
        &b1,
        Some(999.into()),
        &mut proposer_factory,
        &mut block_import,
    );
}

// TODO: Runtime at the moment doesn't implement transactions support, so root block extrinsic
//  verification fails in tests (`submit_test_store_root_block()` doesn't submit extrinsic as such).
// // Check that block import results in archiving working.
// #[test]
// fn archiving_works() {
//     let mut net = SubspaceTestNet::new(1);
//
//     let peer = net.peer(0);
//     let data = peer
//         .data
//         .as_ref()
//         .expect("Subspace link set up during initialization");
//     let client = peer
//         .client()
//         .as_full()
//         .expect("Only full clients are used in tests")
//         .clone();
//
//     let mut proposer_factory = DummyFactory {
//         client: client.clone(),
//         config: data.link.config.clone(),
//         epoch_changes: data.link.epoch_changes.clone(),
//         mutator: Arc::new(|_, _| ()),
//     };
//
//     let mut block_import = data
//         .block_import
//         .lock()
//         .take()
//         .expect("import set up during init");
//
//     let tokio_runtime = sc_cli::build_runtime().unwrap();
//     let task_manager = TaskManager::new(tokio_runtime.handle().clone(), None).unwrap();
//
//     super::start_subspace_archiver(&data.link, client.clone(), &task_manager.spawn_handle());
//
//     let mut archived_segment_notification_stream =
//         data.link.archived_segment_notification_stream.subscribe();
//
//     let (archived_segment_sender, archived_segment_receiver) = mpsc::channel();
//
//     std::thread::spawn(move || {
//         tokio_runtime.block_on(async move {
//             while let Some(archived_segment_notification) =
//                 archived_segment_notification_stream.next().await
//             {
//                 archived_segment_sender
//                     .send(archived_segment_notification)
//                     .unwrap();
//             }
//         });
//     });
//
//     {
//         let mut parent_header = client.header(&BlockId::Number(0)).unwrap().unwrap();
//         for slot_number in 1..250 {
//             let block_hash = propose_and_import_block(
//                 &parent_header,
//                 Some(slot_number.into()),
//                 &mut proposer_factory,
//                 &mut block_import,
//             );
//
//             parent_header = client.header(&BlockId::Hash(block_hash)).unwrap().unwrap();
//         }
//     }
//
//     archived_segment_receiver.recv().unwrap();
// }
