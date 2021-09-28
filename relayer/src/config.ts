import * as dotenv from "dotenv";
import { ParachainConfigType } from './types';

dotenv.config();


type SourceChain = {
  url: string;
  parachains: ParachainConfigType[];
  signerSeed: string;
};

type Config = {
  targetChainUrl: string;
  sourceChainUrls: SourceChain[];
};

// TODO: convert to class
const loadConfig = (): Config => {
  const targetChainUrl = process.env.TARGET_CHAIN_URL;

  if (!targetChainUrl) {
    throw new Error("Target chain endpoint url is not provided");
  }

  return {
    targetChainUrl,
    sourceChainUrls: [
      {
        url: "wss://kusama-rpc.polkadot.io",
        signerSeed: '//Alice',
        parachains: [
          {
            url: "https://kusama-statemine-rpc.paritytech.net",
            paraId: 1000,
            chain: "Statemine",
            signerSeed: '//Bob',
          },
          {
            url: "https://karura.api.onfinality.io/public",
            paraId: 2000,
            chain: "Karura",
            signerSeed: '//Alice',
          },
          {
            url: "https://bifrost-parachain.api.onfinality.io/public",
            paraId: 2001,
            chain: "Bifrost",
            signerSeed: '//Bob',
          },
          {
            url: "https://khala.api.onfinality.io/public",
            paraId: 2004,
            chain: "Khala Network",
            signerSeed: '//Alice',
          },
          {
            url: "https://shiden.api.onfinality.io/public",
            paraId: 2007,
            chain: "Shiden",
            signerSeed: '//Bob',
          },
          {
            url: "https://moonriver.api.onfinality.io/public",
            paraId: 2023,
            chain: "Moonriver",
            signerSeed: '//Alice',
          },
          {
            url: "https://calamari.api.onfinality.io/public",
            paraId: 2084,
            chain: "Calamari",
            signerSeed: '//Bob',
          },
          {
            url: "https://spiritnet.api.onfinality.io/public",
            paraId: 2086,
            chain: "Kilt Spiritnet",
            signerSeed: '//Alice',
          },
          {
            url: "https://basilisk.api.onfinality.io/public",
            paraId: 2090,
            chain: "Basilisk",
            signerSeed: '//Bob',
          },
        ]
      },
    ],
  };
};

export default loadConfig();
