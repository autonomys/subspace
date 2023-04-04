//! Relay implementation for consensus blocks.

use crate::{ProtocolClient, ProtocolServer, RelayClient, RelayServer, RelayServerMessage};
use async_trait::async_trait;
use codec::{Decode, Encode};
use libp2p::PeerId;
use sc_network_common::sync::message::{BlockRequest, FromBlock};
use sc_network_sync::service::network::NetworkServiceHandle;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;

#[derive(Encode, Decode)]
struct ConsensusRequest<Block: BlockT> {
    request: BlockRequest<Block>,
    protocol: Vec<u8>,
}

struct ConsensusRelayClient<Block: BlockT> {
    protocol: Arc<dyn ProtocolClient<FromBlock<Block::Hash, NumberFor<Block>>>>,
    _phantom_data: std::marker::PhantomData<Block>,
}

impl<Block: BlockT> RelayClient for ConsensusRelayClient<Block> {
    type Request = BlockRequest<Block>;

    fn download(&self, _who: PeerId, request: &Self::Request, _network: NetworkServiceHandle) {
        // Send initial message
        let consensus_request: ConsensusRequest<Block> = ConsensusRequest {
            request: request.clone(),
            protocol: self.protocol.build_request(&request.from),
        };
        let msg: RelayServerMessage<ConsensusRequest<Block>> =
            RelayServerMessage::InitialRequest(consensus_request);
        let _bytes = msg.encode();
        // let response = _network.send(bytes).await;
        // let transactions = self.protocol.resolve(response.protocol_data);

        unimplemented!()
    }
}

struct ConsensusRelayServer<Block: BlockT> {
    _protocol: Box<dyn ProtocolServer + Send>,
    _phantom_data: std::marker::PhantomData<Block>,
}

#[async_trait]
impl<Block: BlockT> RelayServer for ConsensusRelayServer<Block> {
    async fn on_message(&mut self) {
        // match message {
        //    Initial request => {
        //         // Fill the non-protocol part for blocks in the block range(ascending/descending)
        //         // For each block, call protocol to fill the protocol response part
        //    },
        //     Reconcile message => {
        //         // Call protocol to handle message, send response back
        //     }
        // }
        unimplemented!()
    }
}

struct CompactBlockClient;

#[async_trait]
impl<DownloadUnitId> ProtocolClient<DownloadUnitId> for CompactBlockClient
where
    DownloadUnitId: Encode + Decode,
{
    fn build_request(&self, download_unit: &DownloadUnitId) -> Vec<u8> {
        download_unit.encode()
    }

    async fn resolve(&self) -> Vec<u8> {
        unimplemented!()
    }
}

struct CompactBlockServer;

impl ProtocolServer for CompactBlockServer {
    fn build_response(&self, _protocol_request: Vec<u8>) -> Vec<u8> {
        unimplemented!()
    }

    fn on_message(&self) {
        unimplemented!()
    }
}

fn build_consensus_relay<Block: BlockT>() -> (
    Arc<ConsensusRelayClient<Block>>,
    Box<ConsensusRelayServer<Block>>,
) {
    let client: ConsensusRelayClient<Block> = ConsensusRelayClient {
        protocol: Arc::new(CompactBlockClient),
        _phantom_data: Default::default(),
    };

    let server: ConsensusRelayServer<Block> = ConsensusRelayServer {
        _protocol: Box::new(CompactBlockServer),
        _phantom_data: Default::default(),
    };

    (Arc::new(client), Box::new(server))
}
