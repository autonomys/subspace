import * as dotenv from "dotenv";

dotenv.config();

type SourceChain = {
  url: string;
  chainId: number;
  parachains: string[];
};

type Config = {
  accountSeed: string;
  targetChainUrl: string;
  sourceChainUrls: SourceChain[];
};

export const loadConfig = (): Config => {
  const accountSeed = process.env.ACCOUNT_SEED;
  const targetChainUrl = process.env.TARGET_CHAIN_URL;

  if (!accountSeed) {
    throw new Error("Seed is not provided");
  }

  if (!targetChainUrl) {
    throw new Error("Target chain endpoint url is not provided");
  }

  return {
    accountSeed,
    targetChainUrl,
    sourceChainUrls: [
      {
        url: "wss://kusama-rpc.polkadot.io",
        chainId: 0,
        parachains: [],
      },
      // "wss://rpc.polkadot.io",
      // Kusama and parachains
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
};
