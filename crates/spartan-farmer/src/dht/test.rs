use super::*;
use client as dht;
use client::ClientConfig;

#[tokio::test]
async fn bootstrap_working() {
    // NOTE: There is no difference between a bootstrap and normal node. Under the hood, they both
    // are the same things.

    let mut clients = Vec::new();
    let mut peeraddr = Vec::new();

    // Consider 5 peers: A, B, C, D and E.
    while clients.len() < 5 {
        let config = ClientConfig {
            bootstrap_nodes: Default::default(),
            listen_addr: None,
        };

        let (mut client, eventloop) = dht::create_connection(&config);

        tokio::spawn(eventloop.run());

        client
            .start_listening("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .await;

        let peerid = client.peerid.clone();
        let listen_addr = client.listeners().await;

        if listen_addr.is_empty() {
            continue;
        }

        clients.push(client);
        peeraddr.push((peerid, listen_addr[0].to_owned()));
    }

    // Connect A --> B, B --> C.
    for i in 1..3 {
        let peerid = peeraddr[i].0.clone();
        let addr = peeraddr[i].1.clone();
        clients[i - 1].dial(peerid, addr).await;
    }

    // Connect D --> E.
    for i in 4..5 {
        let peerid = peeraddr[i].0.clone();
        let addr = peeraddr[i].1.clone();
        clients[i - 1].dial(peerid, addr).await;
    }

    // Connect A --> D.
    let peerid = peeraddr[3].0.clone();
    let addr = peeraddr[3].1.clone();
    clients[0].dial(peerid, addr).await;

    // A should find E.
    let qid = clients[0].bootstrap().await;

    // Keep qeurying the result until we get the event we are looking for.
    loop {
        let result = clients[0].query_result(qid).await;
        if result.contains("[RESULT] This query still has 0 peers remaining.") {
            break;
        }
    }

    let known_peers = clients[0].known_peers().await;
    let peerid = peeraddr[4].0.clone();

    assert!(known_peers.contains(&peerid));
}
