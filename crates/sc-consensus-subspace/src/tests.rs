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

// TODO: Restore in the future, currently tests are mostly broken and useless
// // TODO: Tests need to be fixed, then this can be removed
// #![allow(unused_imports, unused_variables, unused_mut)]
//
// use crate::{
//     extract_pre_digest, slot_duration, start_subspace, NewSlotNotification, SubspaceLink,
//     SubspaceParams, SubspaceVerifier,
// };
// use codec::Encode;
// use futures::channel::oneshot;
// use futures::executor::block_on;
// use futures::{future, SinkExt, StreamExt};
// use log::{debug, trace};
// use parking_lot::Mutex;
// use rand::prelude::*;
// use sc_block_builder::{BlockBuilder, BlockBuilderProvider};
// use sc_client_api::backend::TransactionFor;
// use sc_client_api::{BlockBackend, BlockchainEvents};
// use sc_consensus::block_import::ForkChoiceStrategy;
// use sc_consensus::{
//     BlockCheckParams, BlockImport, BlockImportParams, BoxBlockImport, BoxJustificationImport,
//     ImportResult, Verifier,
// };
// use sc_consensus_slots::{BackoffAuthoringOnFinalizedHeadLagging, SlotProportion};
// use sc_network_test::{
//     BlockImportAdapter, Peer, PeersClient, PeersFullClient, TestClientBuilder,
//     TestClientBuilderExt, TestNetFactory,
// };
// use sc_service::TaskManager;
// use schnorrkel::Keypair;
// use sp_api::HeaderT;
// use sp_blockchain::HeaderBackend;
// use sp_consensus::{
//     BlockOrigin, DisableProofRecording, Environment, NoNetwork as DummyOracle, Proposal, Proposer,
// };
// use sp_consensus_slots::{Slot, SlotDuration};
// use sp_consensus_subspace::digests::{CompatibleDigestItem, PreDigest};
// use sp_consensus_subspace::inherents::InherentDataProvider;
// use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
// use sp_core::crypto::UncheckedFrom;
// use sp_core::traits::SpawnEssentialNamed;
// use sp_inherents::{CreateInherentDataProviders, InherentData};
// use sp_runtime::generic::{BlockId, Digest, DigestItem};
// use sp_runtime::traits::{Block as BlockT, Zero};
// use sp_timestamp::Timestamp;
// use std::cell::RefCell;
// use std::collections::HashMap;
// use std::future::Future;
// use std::marker::PhantomData;
// use std::num::NonZeroU64;
// use std::pin::Pin;
// use std::sync::Arc;
// use std::task::Poll;
// use std::time::Duration;
// use subspace_archiving::archiver::Archiver;
// use subspace_core_primitives::crypto::kzg;
// use subspace_core_primitives::crypto::kzg::{Kzg};
// use subspace_core_primitives::objects::BlockObjectMapping;
// use subspace_core_primitives::{
//     ArchivedHistorySegment, FlatPieces, HistorySize, Piece, PieceIndex, PieceOffset, Solution,
// };
// use subspace_proof_of_space::shim::ShimTable;
// use subspace_core_primitives::REWARD_SIGNING_CONTEXT;
// use substrate_test_runtime::{Block as TestBlock, Hash};
// use tokio::runtime::{Handle, Runtime};
//
// type PosTable = ShimTable;
//
// type TestClient = substrate_test_runtime_client::client::Client<
//     substrate_test_runtime_client::Backend,
//     substrate_test_runtime_client::ExecutorDispatch,
//     TestBlock,
//     substrate_test_runtime_client::runtime::RuntimeApi,
// >;
//
// #[derive(Copy, Clone, PartialEq)]
// enum Stage {
//     PreSeal,
//     PostSeal,
// }
//
// type Mutator = Arc<dyn Fn(&mut TestHeader, Stage) + Send + Sync>;
//
// #[derive(Clone)]
// pub struct TestCreateInherentDataProviders {
//     inner: Arc<
//         dyn CreateInherentDataProviders<
//             TestBlock,
//             SubspaceLink<TestBlock>,
//             InherentDataProviders = (InherentDataProvider,),
//         >,
//     >,
// }
//
// #[async_trait::async_trait]
// impl CreateInherentDataProviders<TestBlock, SubspaceLink<TestBlock>>
//     for TestCreateInherentDataProviders
// {
//     type InherentDataProviders = (InherentDataProvider,);
//
//     async fn create_inherent_data_providers(
//         &self,
//         parent: <TestBlock as BlockT>::Hash,
//         extra_args: SubspaceLink<TestBlock>,
//     ) -> Result<Self::InherentDataProviders, Box<dyn std::error::Error + Send + Sync>> {
//         self.inner
//             .create_inherent_data_providers(parent, extra_args)
//             .await
//     }
// }
//
// type SubspaceBlockImport = PanickingBlockImport<
//     crate::SubspaceBlockImport<
//         PosTable,
//         TestBlock,
//         TestClient,
//         Arc<TestClient>,
//         TestCreateInherentDataProviders,
//     >,
// >;
//
// type SubspaceProposal =
//     Proposal<TestBlock, TransactionFor<substrate_test_runtime_client::Backend, TestBlock>, ()>;
//
// #[derive(Clone)]
// struct DummyFactory {
//     client: Arc<TestClient>,
//     mutator: Mutator,
// }
//
// struct DummyProposer {
//     factory: DummyFactory,
//     parent_hash: Hash,
// }
//
// impl Environment<TestBlock> for DummyFactory {
//     type CreateProposer = future::Ready<Result<DummyProposer, Self::Error>>;
//     type Proposer = DummyProposer;
//     type Error = sp_blockchain::Error;
//
//     fn init(&mut self, parent_header: &<TestBlock as BlockT>::Header) -> Self::CreateProposer {
//         future::ready(Ok(DummyProposer {
//             factory: self.clone(),
//             parent_hash: parent_header.hash(),
//         }))
//     }
// }
//
// impl DummyProposer {
//     fn propose_with(
//         &mut self,
//         pre_digests: Digest,
//     ) -> future::Ready<Result<SubspaceProposal, sp_blockchain::Error>> {
//         let block_builder = self
//             .factory
//             .client
//             .new_block_at(self.parent_hash, pre_digests, false)
//             .unwrap();
//
//         let mut block = match block_builder.build() {
//             Ok(b) => b.block,
//             Err(e) => return future::ready(Err(e)),
//         };
//
//         {
//             let digest = DigestItem::solution_range(u64::MAX);
//             block.header.digest_mut().push(digest);
//         }
//
//         // mutate the block header according to the mutator.
//         (self.factory.mutator)(&mut block.header, Stage::PreSeal);
//
//         future::ready(Ok(Proposal {
//             block,
//             proof: (),
//             storage_changes: Default::default(),
//         }))
//     }
// }
//
// impl Proposer<TestBlock> for DummyProposer {
//     type Error = sp_blockchain::Error;
//     type Transaction = TransactionFor<substrate_test_runtime_client::Backend, TestBlock>;
//     type Proposal = future::Ready<Result<SubspaceProposal, Self::Error>>;
//     type ProofRecording = DisableProofRecording;
//     type Proof = ();
//
//     fn propose(
//         mut self,
//         _: InherentData,
//         pre_digests: Digest,
//         _: Duration,
//         _: Option<usize>,
//     ) -> Self::Proposal {
//         self.propose_with(pre_digests)
//     }
// }
//
// thread_local! {
//     static MUTATOR: RefCell<Mutator> = RefCell::new(Arc::new(|_, _|()));
// }
//
// #[derive(Clone)]
// pub struct PanickingBlockImport<B> {
//     block_import: B,
//     link: SubspaceLink<TestBlock>,
// }
//
// #[async_trait::async_trait]
// impl<B: BlockImport<TestBlock>> BlockImport<TestBlock> for PanickingBlockImport<B>
// where
//     B::Transaction: Send,
//     B: Send,
// {
//     type Error = B::Error;
//     type Transaction = B::Transaction;
//
//     async fn import_block(
//         &mut self,
//         block: BlockImportParams<TestBlock, Self::Transaction>,
//     ) -> Result<ImportResult, Self::Error> {
//         // TODO: Here we are hacking around lack of transaction support in test runtime and
//         //  remove known segment headers for current block to make sure block import doesn't fail,
//         //  this should be removed once runtime supports transactions
//         let block_number = block.header.number;
//         let removed_segment_headers = self.link.segment_headers.lock().pop(&block_number);
//
//         let import_result = self
//             .block_import
//             .import_block(block)
//             .await
//             .expect("importing block failed");
//
//         if let Some(removed_segment_headers) = removed_segment_headers {
//             self.link
//                 .segment_headers
//                 .lock()
//                 .put(block_number, removed_segment_headers);
//         }
//
//         Ok(import_result)
//     }
//
//     async fn check_block(
//         &mut self,
//         block: BlockCheckParams<TestBlock>,
//     ) -> Result<ImportResult, Self::Error> {
//         Ok(self
//             .block_import
//             .check_block(block)
//             .await
//             .expect("checking block failed"))
//     }
// }
//
// type SubspacePeer = Peer<Option<PeerData>, SubspaceBlockImport>;
//
// pub struct SubspaceTestNet {
//     peers: Vec<SubspacePeer>,
//     kzg: Kzg,
// }
//
// type TestHeader = <TestBlock as BlockT>::Header;
//
// type TestSelectChain =
//     substrate_test_runtime_client::LongestChain<substrate_test_runtime_client::Backend, TestBlock>;
//
// pub struct TestVerifier {
//     inner: SubspaceVerifier<
//         PosTable,
//         TestBlock,
//         PeersFullClient,
//         TestSelectChain,
//         Box<dyn Fn() -> Slot + Send + Sync + 'static>,
//     >,
//     mutator: Mutator,
// }
//
// #[async_trait::async_trait]
// impl Verifier<TestBlock> for TestVerifier {
//     /// Verify the given data and return the BlockImportParams and an optional
//     /// new set of validators to import. If not, err with an Error-Message
//     /// presented to the User in the logs.
//     async fn verify(
//         &mut self,
//         mut block: BlockImportParams<TestBlock, ()>,
//     ) -> Result<BlockImportParams<TestBlock, ()>, String> {
//         // apply post-sealing mutations (i.e. stripping seal, if desired).
//         (self.mutator)(&mut block.header, Stage::PostSeal);
//         self.inner.verify(block).await
//     }
// }
//
// pub struct PeerData {
//     link: SubspaceLink<TestBlock>,
//     block_import: Mutex<
//         Option<
//             BoxBlockImport<
//                 TestBlock,
//                 TransactionFor<substrate_test_runtime_client::Backend, TestBlock>,
//             >,
//         >,
//     >,
// }
//
// impl TestNetFactory for SubspaceTestNet {
//     type Verifier = TestVerifier;
//     type PeerData = Option<PeerData>;
//     type BlockImport = SubspaceBlockImport;
//
//     fn new(n: usize) -> Self {
//         trace!(target: "test_network", "Creating test network");
//         let kzg = Kzg::new(kzg::embedded_kzg_settings());
//         let mut net = Self {
//             peers: Vec::with_capacity(n),
//             kzg,
//         };
//
//         for i in 0..n {
//             trace!(target: "test_network", "Adding peer {}", i);
//             net.add_full_peer();
//         }
//         net
//     }
//
//     fn make_block_import(
//         &self,
//         client: PeersClient,
//     ) -> (
//         BlockImportAdapter<Self::BlockImport>,
//         Option<BoxJustificationImport<TestBlock>>,
//         Option<PeerData>,
//     ) {
//         let client = client.as_client();
//
//         let slot_duration = slot_duration(&*client).expect("slot duration available");
//         let (block_import, link) = crate::block_import(
//             slot_duration,
//             client.clone(),
//             client,
//             self.kzg.clone(),
//             TestCreateInherentDataProviders {
//                 inner: Arc::new(|_, _| async {
//                     let slot = InherentDataProvider::from_timestamp_and_slot_duration(
//                         Timestamp::current(),
//                         SlotDuration::from_millis(6000),
//                         vec![],
//                     );
//
//                     Ok((slot,))
//                 }),
//             },
//         )
//         .expect("can initialize block-import");
//
//         let block_import = PanickingBlockImport {
//             block_import,
//             link: link.clone(),
//         };
//
//         let data_block_import =
//             Mutex::new(Some(Box::new(block_import.clone()) as BoxBlockImport<_, _>));
//         (
//             BlockImportAdapter::new(block_import),
//             None,
//             Some(PeerData {
//                 link,
//                 block_import: data_block_import,
//             }),
//         )
//     }
//
//     fn make_verifier(&self, client: PeersClient, _maybe_link: &Option<PeerData>) -> Self::Verifier {
//         use substrate_test_runtime_client::DefaultTestClientBuilderExt;
//
//         let client = client.as_client();
//         trace!(target: "subspace", "Creating a verifier");
//
//         let (_, longest_chain) = TestClientBuilder::new().build_with_longest_chain();
//
//         TestVerifier {
//             inner: SubspaceVerifier {
//                 client,
//                 kzg: self.kzg.clone(),
//                 select_chain: longest_chain,
//                 slot_now: Box::new(|| {
//                     Slot::from_timestamp(Timestamp::current(), SlotDuration::from_millis(6000))
//                 }),
//                 telemetry: None,
//                 reward_signing_context: schnorrkel::context::signing_context(
//                     REWARD_SIGNING_CONTEXT,
//                 ),
//                 is_authoring_blocks: true,
//                 _pos_table: PhantomData::<PosTable>,
//                 _block: PhantomData,
//             },
//             mutator: MUTATOR.with(|m| m.borrow().clone()),
//         }
//     }
//
//     fn peer(&mut self, i: usize) -> &mut SubspacePeer {
//         trace!(target: "subspace", "Retrieving a peer");
//         &mut self.peers[i]
//     }
//
//     fn peers(&self) -> &Vec<SubspacePeer> {
//         trace!(target: "subspace", "Retrieving peers");
//         &self.peers
//     }
//
//     fn peers_mut(&mut self) -> &mut Vec<SubspacePeer> {
//         &mut self.peers
//     }
//
//     fn mut_peers<F: FnOnce(&mut Vec<SubspacePeer>)>(&mut self, closure: F) {
//         closure(&mut self.peers);
//     }
// }
//
// #[test]
// #[should_panic]
// fn rejects_empty_block() {
//     sp_tracing::try_init_simple();
//     let mut net = SubspaceTestNet::new(3);
//     let block_builder = |builder: BlockBuilder<_, _, _>| builder.build().unwrap().block;
//     net.mut_peers(|peer| {
//         peer[0].generate_blocks(1, BlockOrigin::NetworkInitialSync, block_builder);
//     })
// }
//
// fn get_archived_segments(client: &TestClient) -> Vec<ArchivedHistorySegment> {
//     let kzg = Kzg::new(kzg::embedded_kzg_settings());
//     let mut archiver = Archiver::new(kzg).expect("Incorrect parameters for archiver");
//
//     let genesis_block = client.block(client.info().genesis_hash).unwrap().unwrap();
//     archiver
//         .add_block(genesis_block.encode(), BlockObjectMapping::default())
//         .into_iter()
//         .map(|archived_segment| archived_segment.pieces)
//         .collect()
// }
//
// async fn run_one_test(mutator: impl Fn(&mut TestHeader, Stage) + Send + Sync + 'static) {
//     sp_tracing::try_init_simple();
//     let mutator = Arc::new(mutator) as Mutator;
//
//     MUTATOR.with(|m| *m.borrow_mut() = mutator.clone());
//     let mut net = SubspaceTestNet::new(3);
//
//     let net = Arc::new(Mutex::new(net));
//     let mut import_notifications = Vec::new();
//     let mut subspace_futures = Vec::<Pin<Box<dyn Future<Output = ()>>>>::new();
//
//     for peer_id in [0, 1, 2_usize].iter() {
//         let mut net = net.lock();
//         let peer = net.peer(*peer_id);
//         let client = peer.client().as_client().clone();
//         let select_chain = peer.select_chain().expect("Full client has select_chain");
//
//         let mut got_own = false;
//         let mut got_other = false;
//
//         let data = peer
//             .data
//             .as_ref()
//             .expect("Subspace link set up during initialization");
//
//         let environ = DummyFactory {
//             client: client.clone(),
//             mutator: mutator.clone(),
//         };
//
//         import_notifications.push(
//             // run each future until we get one of our own blocks with number higher than 5
//             // that was produced locally.
//             client
//                 .import_notification_stream()
//                 .take_while(move |n| {
//                     future::ready(
//                         n.header.number() < &5 || {
//                             if n.origin == BlockOrigin::Own {
//                                 got_own = true;
//                             } else {
//                                 got_other = true;
//                             }
//
//                             // continue until we have at least one block of our own
//                             // and one of another peer.
//                             !(got_own && got_other)
//                         },
//                     )
//                 })
//                 .for_each(|_| future::ready(())),
//         );
//
//         let task_manager =
//             TaskManager::new(sc_cli::build_runtime().unwrap().handle().clone(), None).unwrap();
//
//         let subspace_archiver = super::create_subspace_archiver(&data.link, client.clone(), None);
//
//         task_manager
//             .spawn_essential_handle()
//             .spawn_essential_blocking("subspace-archiver", None, Box::pin(subspace_archiver));
//
//         let (archived_pieces_sender, archived_pieces_receiver) = oneshot::channel();
//
//         std::thread::spawn({
//             let client = Arc::clone(&client);
//
//             move || {
//                 let archived_pieces = get_archived_segments(&client);
//                 archived_pieces_sender.send(archived_pieces).unwrap();
//             }
//         });
//
//         let subspace_worker =
//             start_subspace::<PosTable, _, _, _, _, _, _, _, _, _, _>(SubspaceParams {
//                 block_import: data
//                     .block_import
//                     .lock()
//                     .take()
//                     .expect("import set up during init"),
//                 select_chain,
//                 client,
//                 env: environ,
//                 sync_oracle: DummyOracle,
//                 create_inherent_data_providers: Box::new(|_, _| async {
//                     let slot = InherentDataProvider::from_timestamp_and_slot_duration(
//                         Timestamp::current(),
//                         SlotDuration::from_millis(6000),
//                         vec![],
//                     );
//
//                     Ok((slot,))
//                 }),
//                 force_authoring: false,
//                 backoff_authoring_blocks: Some(BackoffAuthoringOnFinalizedHeadLagging::default()),
//                 subspace_link: data.link.clone(),
//                 justification_sync_link: (),
//                 block_proposal_slot_portion: SlotProportion::new(0.9),
//                 max_block_proposal_slot_portion: None,
//                 telemetry: None,
//             })
//             .expect("Starts Subspace");
//
//         let mut new_slot_notification_stream = data.link.new_slot_notification_stream().subscribe();
//         let subspace_farmer = async move {
//             let keypair = Keypair::generate();
//             let (piece_index, mut encoding) = archived_pieces_receiver
//                 .await
//                 .unwrap()
//                 .iter()
//                 .flat_map(|flat_pieces| flat_pieces.iter())
//                 .enumerate()
//                 .choose(&mut thread_rng())
//                 .map(|(piece_index, piece)| (piece_index as u64, Piece::from(piece)))
//                 .unwrap();
//
//             while let Some(NewSlotNotification {
//                 new_slot_info,
//                 mut solution_sender,
//             }) = new_slot_notification_stream.next().await
//             {
//                 if Into::<u64>::into(new_slot_info.slot) % 3 == (*peer_id) as u64 {
//                     // TODO: Update implementation for V2 consensus
//                     // let tag: Tag = create_tag(&encoding, new_slot_info.salt);
//                     //
//                     // let _ = solution_sender
//                     //     .send(Solution {
//                     //         public_key: FarmerPublicKey::from_bytes(keypair.public.to_bytes()),
//                     //         reward_address: FarmerPublicKey::from_bytes(
//                     //             keypair.public.to_bytes(),
//                     //         ),
//                     //         piece_index,
//                     //         encoding: encoding.clone(),
//                     //         tag_signature: create_chunk_signature(&keypair, tag),
//                     //         sector_slot_challenge: derive_sector_slot_challenge(
//                     //             &keypair,
//                     //             new_slot_info.global_challenge,
//                     //         ),
//                     //         tag,
//                     //     })
//                     //     .await;
//                 }
//             }
//         };
//
//         subspace_futures.push(Box::pin(subspace_worker));
//         subspace_futures.push(Box::pin(subspace_farmer));
//     }
//     future::select(
//         futures::future::poll_fn(move |cx| {
//             let mut net = net.lock();
//             net.poll(cx);
//             for p in net.peers() {
//                 for (h, e) in p.failed_verifications() {
//                     panic!("Verification failed for {h:?}: {e}");
//                 }
//             }
//
//             Poll::<()>::Pending
//         }),
//         future::select(
//             future::join_all(import_notifications),
//             future::join_all(subspace_futures),
//         ),
//     )
//     .await;
// }
//
// // TODO: Un-ignore once `submit_test_store_segment_header()` is working or transactions are
// //  supported in test runtime
// #[tokio::test]
// #[ignore]
// async fn authoring_blocks() {
//     run_one_test(|_, _| ()).await;
// }
//
// #[tokio::test]
// #[should_panic]
// async fn rejects_missing_inherent_digest() {
//     run_one_test(|header: &mut TestHeader, stage| {
//         let v = std::mem::take(&mut header.digest_mut().logs);
//         header.digest_mut().logs = v
//             .into_iter()
//             .filter(|v| {
//                 stage == Stage::PostSeal
//                     || DigestItem::as_subspace_pre_digest::<FarmerPublicKey>(v).is_none()
//             })
//             .collect()
//     })
//     .await;
// }
//
// #[tokio::test]
// #[should_panic]
// async fn rejects_missing_seals() {
//     run_one_test(|header: &mut TestHeader, stage| {
//         let v = std::mem::take(&mut header.digest_mut().logs);
//         header.digest_mut().logs = v
//             .into_iter()
//             .filter(|v| stage == Stage::PreSeal || DigestItem::as_subspace_seal(v).is_none())
//             .collect()
//     })
//     .await;
// }
//
// #[test]
// fn wrong_consensus_engine_id_rejected() {
//     sp_tracing::try_init_simple();
//     let keypair = Keypair::generate();
//     let ctx = schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT);
//     let bad_seal = DigestItem::Seal([0; 4], keypair.sign(ctx.bytes(b"")).to_bytes().to_vec());
//     assert!(CompatibleDigestItem::as_subspace_pre_digest::<FarmerPublicKey>(&bad_seal).is_none());
//     assert!(CompatibleDigestItem::as_subspace_seal(&bad_seal).is_none())
// }
//
// #[test]
// fn malformed_pre_digest_rejected() {
//     sp_tracing::try_init_simple();
//     let bad_seal = DigestItem::subspace_seal(FarmerSignature::from_bytes([0u8; 64]));
//     assert!(CompatibleDigestItem::as_subspace_pre_digest::<FarmerPublicKey>(&bad_seal).is_none());
// }
//
// #[test]
// fn sig_is_not_pre_digest() {
//     sp_tracing::try_init_simple();
//     let keypair = Keypair::generate();
//     let ctx = schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT);
//     let bad_seal = DigestItem::subspace_seal(FarmerSignature::from_bytes(
//         keypair.sign(ctx.bytes(b"")).to_bytes(),
//     ));
//     assert!(CompatibleDigestItem::as_subspace_pre_digest::<FarmerPublicKey>(&bad_seal).is_none());
//     assert!(CompatibleDigestItem::as_subspace_seal(&bad_seal).is_some())
// }
//
// /// Claims the given slot number. always returning a dummy block.
// pub fn dummy_claim_slot(
//     slot: Slot,
// ) -> Option<(PreDigest<FarmerPublicKey, FarmerPublicKey>, FarmerPublicKey)> {
//     Some((
//         PreDigest {
//             solution: Solution {
//                 public_key: FarmerPublicKey::from_bytes([0u8; 32]),
//                 reward_address: FarmerPublicKey::from_bytes([0u8; 32]),
//                 sector_index: 0,
//                 history_size: HistorySize::from(NonZeroU64::new(1).unwrap()),
//                 piece_offset: PieceOffset::default(),
//                 record_commitment: Default::default(),
//                 record_witness: Default::default(),
//                 chunk: Default::default(),
//                 chunk_witness: Default::default(),
//                 proof_of_space: Default::default(),
//             },
//             slot,
//         },
//         FarmerPublicKey::from_bytes([0u8; 32]),
//     ))
// }
//
// #[test]
// fn can_author_block() {
//     sp_tracing::try_init_simple();
//
//     let mut i = 0;
//
//     // we might need to try a couple of times
//     loop {
//         match dummy_claim_slot(i.into()) {
//             None => i += 1,
//             Some(s) => {
//                 debug!(target: "subspace", "Authored block {:?}", s.0);
//                 break;
//             }
//         }
//     }
// }
//
// // Propose and import a new Subspace block on top of the given parent.
// fn propose_and_import_block<Transaction: Send + 'static>(
//     parent: &TestHeader,
//     slot: Option<Slot>,
//     proposer_factory: &mut DummyFactory,
//     block_import: &mut BoxBlockImport<TestBlock, Transaction>,
// ) -> sp_core::H256 {
//     // TODO: Update implementation for V2 consensus
//     // let mut proposer = futures::executor::block_on(proposer_factory.init(parent)).unwrap();
//     //
//     // let slot = slot.unwrap_or_else(|| {
//     //     let parent_pre_digest = extract_pre_digest::<TestHeader>(parent).unwrap();
//     //     parent_pre_digest.slot + 1
//     // });
//     //
//     // let keypair = Keypair::generate();
//     // let ctx = schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT);
//     //
//     // let (pre_digest, signature) = {
//     //     let encoding = Piece::default();
//     //     let tag: Tag = [0u8; 8];
//     //
//     //     (
//     //         sp_runtime::generic::Digest {
//     //             logs: vec![DigestItem::subspace_pre_digest(&PreDigest {
//     //                 slot,
//     //                 solution: Solution {
//     //                     public_key: FarmerPublicKey::from_bytes(keypair.public.to_bytes()),
//     //                     reward_address: FarmerPublicKey::from_bytes(keypair.public.to_bytes()),
//     //                     piece_index: 0,
//     //                     encoding,
//     //                     tag_signature: create_chunk_signature(&keypair, tag),
//     //                     sector_slot_challenge: LocalChallenge {
//     //                         output: [0; 32],
//     //                         proof: [0; 64],
//     //                     },
//     //                     tag,
//     //                 },
//     //             })],
//     //         },
//     //         keypair.sign(ctx.bytes(&[])).to_bytes(),
//     //     )
//     // };
//     //
//     // let mut block = futures::executor::block_on(proposer.propose_with(pre_digest))
//     //     .unwrap()
//     //     .block;
//     //
//     // let seal = DigestItem::subspace_seal(signature.to_vec().try_into().unwrap());
//     //
//     // let post_hash = {
//     //     block.header.digest_mut().push(seal.clone());
//     //     let h = block.header.hash();
//     //     block.header.digest_mut().pop();
//     //     h
//     // };
//     //
//     // let mut import = BlockImportParams::new(BlockOrigin::Own, block.header);
//     // import.post_digests.push(seal);
//     // import.body = Some(block.extrinsics);
//     // import.fork_choice = Some(ForkChoiceStrategy::LongestChain);
//     // let import_result = block_on(block_import.import_block(import, Default::default())).unwrap();
//     //
//     // match import_result {
//     //     ImportResult::Imported(_) => {}
//     //     _ => panic!("expected block to be imported"),
//     // }
//     //
//     // post_hash
//     todo!()
// }
//
// #[test]
// #[should_panic]
// fn verify_slots_are_strictly_increasing() {
//     let mut net = SubspaceTestNet::new(1);
//
//     let peer = net.peer(0);
//     let data = peer
//         .data
//         .as_ref()
//         .expect("Subspace link set up during initialization");
//
//     let client = peer.client().as_client();
//     let mut block_import = data
//         .block_import
//         .lock()
//         .take()
//         .expect("import set up during init");
//
//     let mut proposer_factory = DummyFactory {
//         client: client.clone(),
//         mutator: Arc::new(|_, _| ()),
//     };
//
//     let genesis_header = client.header(client.info().genesis_hash).unwrap().unwrap();
//
//     // we should have no issue importing this block
//     let b1 = propose_and_import_block(
//         &genesis_header,
//         Some(999.into()),
//         &mut proposer_factory,
//         &mut block_import,
//     );
//
//     let b1 = client.header(b1).unwrap().unwrap();
//
//     // we should fail to import this block since the slot number didn't increase.
//     // we will panic due to the `PanickingBlockImport` defined above.
//     propose_and_import_block(
//         &b1,
//         Some(999.into()),
//         &mut proposer_factory,
//         &mut block_import,
//     );
// }
//
// // TODO: Runtime at the moment doesn't implement transactions support, so segment header extrinsic
// //  verification fails in tests (`submit_test_store_segment_header()` doesn't submit extrinsic as
// //  such).
// // // Check that block import results in archiving working.
// // #[test]
// // fn archiving_works() {
// //    let mut net = SubspaceTestNet::new(1);
// //
// //     let peer = net.peer(0);
// //     let data = peer
// //         .data
// //         .as_ref()
// //         .expect("Subspace link set up during initialization");
// //     let client = peer
// //         .client()
// //         .as_client()
// //         .clone();
// //
// //     let mut proposer_factory = DummyFactory {
// //         client: client.clone(),
// //         config: data.link.config.clone(),
// //         epoch_changes: data.link.epoch_changes.clone(),
// //         mutator: Arc::new(|_, _| ()),
// //     };
// //
// //     let mut block_import = data
// //         .block_import
// //         .lock()
// //         .take()
// //         .expect("import set up during init");
// //
// //     let tokio_runtime = sc_cli::build_runtime().unwrap();
// //     let task_manager = TaskManager::new(tokio_None).unwrap();
// //
// //     super::start_subspace_archiver(&data.link, client.clone(), &task_manager.spawn_essential_handle());
// //
// //     let mut archived_segment_notification_stream =
// //         data.link.archived_segment_notification_stream.subscribe();
// //
// //     let (archived_segment_sender, archived_segment_receiver) = mpsc::channel();
// //
// //     std::thread::spawn(move || {
// //         tokio_runtime.block_on(async move {
// //             while let Some(archived_segment_notification) =
// //                 archived_segment_notification_stream.next().await
// //             {
// //                 archived_segment_sender
// //                     .send(archived_segment_notification)
// //                     .unwrap();
// //             }
// //         });
// //     });
// //
// //     {
// //         let mut parent_header = client.header(&BlockId::Number(0)).unwrap().unwrap();
// //         for slot_number in 1..250 {
// //             let block_hash = propose_and_import_block(
// //                 &parent_header,
// //                 Some(slot_number.into()),
// //                 &mut proposer_factory,
// //                 &mut block_import,
// //             );
// //
// //             parent_header = client.header(&BlockId::Hash(block_hash)).unwrap().unwrap();
// //         }
// //     }
// //
// //     archived_segment_receiver.recv().unwrap();
// // }
