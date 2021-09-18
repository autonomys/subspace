import * as dotenv from "dotenv";

dotenv.config();

type SourceChain = {
  url: string;
  chainId: number;
  parachains: Record<string, string>;
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
        parachains: {
          [1000]: "wss://kusama-statemine-rpc.paritytech.net",
          [2000]: "wss://karura-rpc-3.aca-api.network/ws",
          [2001]: "wss://bifrost-rpc.liebi.com/ws",
          [2004]: "wss://khala-api.phala.network/ws",
          [2007]: "wss://rpc.shiden.astar.network",
          [2023]: "wss://wss.moonriver.moonbeam.network",
          [2084]: "wss://falafel.calamari.systems/",
          [2086]: "wss://spiritnet.kilt.io/",
        },
      },
    ],
  };
};
