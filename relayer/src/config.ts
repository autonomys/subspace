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

// TODO: convert to class
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
        parachains: [
          // TODO: add parachains
          // "wss://kusama-statemine-rpc.paritytech.net",
          // "wss://karura-rpc-3.aca-api.network/ws", // requires custom types
          // "wss://bifrost-rpc.liebi.com/ws", // requires custom types
          // "wss://khala-api.phala.network/ws", // requires custom types
          // "wss://rpc.shiden.astar.network",
          // "wss://wss.moonriver.moonbeam.network", // requires custom types
          // "wss://spiritnet.kilt.io/",
        ],
      },
    ],
  };
};
