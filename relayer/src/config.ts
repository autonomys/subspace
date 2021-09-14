import * as dotenv from "dotenv";

dotenv.config();

const config = {
  accountSeed: process.env.ACCOUNT_SEED,
  targetChainUrl: process.env.TARGET_CHAIN_URL,
  sourceChainUrls: [
    "wss://rpc.polkadot.io",
    "wss://kusama-rpc.polkadot.io",
    "wss://pub.elara.patract.io/westend",
    "wss://fullnode.centrifuge.io",
    "wss://mainnet-node.dock.io",
    "wss://rpc.plasmnet.io/",
    "wss://rpc.kulupu.corepaper.org/ws",
    "wss://blockchain.crownsterling.io",
    "wss://rpc.neatcoin.org/ws",
    "wss://main3.nodleprotocol.io",
    "wss://rpc.shiden.astar.network",
    "wss://mainnet.subgame.org/",
    "wss://westlake.datahighway.com",
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
