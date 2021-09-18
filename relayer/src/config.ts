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
          [1000]: "https://kusama-statemine-rpc.paritytech.net",
          [2000]: "https://karura.api.onfinality.io/public",
          [2001]: "https://bifrost-parachain.api.onfinality.io/public",
          [2004]: "https://khala.api.onfinality.io/public",
          [2007]: "https://shiden.api.onfinality.io/public",
          [2023]: "https://moonriver.api.onfinality.io/public",
          [2084]: "https://calamari.api.onfinality.io/public",
          [2086]: "https://spiritnet.api.onfinality.io/public",
        },
      },
    ],
  };
};
