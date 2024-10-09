use crate::protocols::request_response::handlers::cached_piece_by_index::ClosestPeers;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use parity_scale_codec::{Decode, Encode};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn closest_peers_encoding() {
    // Basic encoding/decoding
    {
        let closest_peers = ClosestPeers::from(vec![
            {
                let peer_id = PeerId::random();
                let addresses = vec![Multiaddr::from(IpAddr::V4(Ipv4Addr::LOCALHOST))
                    .with(Protocol::Tcp(1234))
                    .with_p2p(peer_id)
                    .unwrap()];

                (peer_id, addresses)
            },
            {
                let peer_id = PeerId::random();
                let addresses = vec![
                    Multiaddr::from(IpAddr::V4(Ipv4Addr::LOCALHOST))
                        .with(Protocol::Tcp(1234))
                        .with_p2p(peer_id)
                        .unwrap(),
                    Multiaddr::from(IpAddr::V6(Ipv6Addr::LOCALHOST))
                        .with(Protocol::Udp(1234))
                        .with_p2p(peer_id)
                        .unwrap(),
                ];

                (peer_id, addresses)
            },
        ]);

        let decoded_closest_peers =
            ClosestPeers::decode(&mut closest_peers.encode().as_ref()).unwrap();
        assert_eq!(closest_peers, decoded_closest_peers);
    }

    // Addresses must end with `/p2p`
    {
        let closest_peers = ClosestPeers::from(vec![{
            let peer_id = PeerId::random();
            let addresses =
                vec![Multiaddr::from(IpAddr::V4(Ipv4Addr::LOCALHOST)).with(Protocol::Tcp(1234))];

            (peer_id, addresses)
        }]);

        assert!(ClosestPeers::decode(&mut closest_peers.encode().as_ref()).is_err());
    }

    // Addresses must end with correct `/p2p`
    {
        let closest_peers = ClosestPeers::from(vec![{
            let peer_id = PeerId::random();
            let addresses = vec![Multiaddr::from(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .with(Protocol::Tcp(1234))
                .with_p2p(PeerId::random())
                .unwrap()];

            (peer_id, addresses)
        }]);

        assert!(ClosestPeers::decode(&mut closest_peers.encode().as_ref()).is_err());
    }

    // Addresses list must not be empty
    {
        let closest_peers = ClosestPeers::from(vec![(PeerId::random(), vec![])]);

        assert!(ClosestPeers::decode(&mut closest_peers.encode().as_ref()).is_err());
    }
}
