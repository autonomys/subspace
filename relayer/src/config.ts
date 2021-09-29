import * as dotenv from "dotenv";
import { ParachainConfigType } from './types';

dotenv.config();

interface SourceChain {
  url: string;
  parachains: ParachainConfigType[];
}

interface Config {
  accountSeed: string;
  targetChainUrl: string;
  sourceChainUrls: SourceChain[];
}

// TODO: convert to class
const loadConfig = (): Config => {
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
        parachains: [
          {
            url: "https://kusama-statemine-rpc.paritytech.net",
            paraId: 1000,
            chain: "Statemine",
          },
          {
            url: "https://karura.api.onfinality.io/public",
            paraId: 2000,
            chain: "Karura",
          },
          {
            url: "https://bifrost-parachain.api.onfinality.io/public",
            paraId: 2001,
            chain: "Bifrost",
          },
          {
            url: "https://khala.api.onfinality.io/public",
            paraId: 2004,
            chain: "Khala Network",
          },
          {
            url: "https://shiden.api.onfinality.io/public",
            paraId: 2007,
            chain: "Shiden",
          },
          {
            url: "https://moonriver.api.onfinality.io/public",
            paraId: 2023,
            chain: "Moonriver",
          },
          {
            url: "https://calamari.api.onfinality.io/public",
            paraId: 2084,
            chain: "Calamari",
          },
          {
            url: "https://spiritnet.api.onfinality.io/public",
            paraId: 2086,
            chain: "Kilt Spiritnet",
          },
          {
            url: "https://basilisk.api.onfinality.io/public",
            paraId: 2090,
            chain: "Basilisk",
          },
        ]
      },
    ],
  };
};

export default loadConfig();
