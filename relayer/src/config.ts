import * as dotenv from "dotenv";

dotenv.config();

const config = {
  accountSeed: process.env.ACCOUNT_SEED,
  targetChainUrl: process.env.TARGET_CHAIN_URL,
  sourceChainUrls: [
    // "wss://rpc.polkadot.io",
    // Kusama and parachains
    "wss://kusama-rpc.polkadot.io",
    // "wss://kusama-statemine-rpc.paritytech.net",
    // "wss://karura-rpc-3.aca-api.network/ws", // requires custom types
    // "wss://bifrost-rpc.liebi.com/ws", // requires custom types
    // "wss://khala-api.phala.network/ws", // requires custom types
    // "wss://rpc.shiden.astar.network",
    // "wss://wss.moonriver.moonbeam.network", // requires custom types
    // "wss://spiritnet.kilt.io/",
    // Other
    // "wss://pub.elara.patract.io/westend",
    // "wss://fullnode.centrifuge.io",
    // "wss://mainnet-node.dock.io",
    // "wss://rpc.plasmnet.io/",
    // "wss://rpc.kulupu.corepaper.org/ws",
    // "wss://blockchain.crownsterling.io",
    // "wss://rpc.neatcoin.org/ws",
    // "wss://main3.nodleprotocol.io",
    // "wss://rpc.shiden.astar.network",
    // "wss://mainnet.subgame.org/",
    // "wss://westlake.datahighway.com",
    // chains below require custom types provision
    // "wss://rpc.subsocial.network",
    // "wss://mainnet.uniarts.vip:9443",
    // "wss://wss.spannerprotocol.com",
    // "wss://mof2.sora.org",
    // "wss://rpc.darwinia.network",
    // "wss://node.equilibrium.io",
    // "wss://rpc-02.snakenet.hydradx.io",
    // "wss://pub.elara.patract.io/chainx",
    // "wss://mainnet.edgewa.re",
    // "wss://node.genshiro.io",
    // "wss://node.v1.riochain.io",
    // "wss://kusama.rpc.robonomics.network/",
  ],
};

export default config;
