import * as dotenv from "dotenv";

dotenv.config();

const config = {
  accountSeed: process.env.ACCOUNT_SEED,
  targetChainUrl: process.env.TARGET_CHAIN_URL,
  sourceChainUrls: [
    "wss://kusama-rpc.polkadot.io",
    "wss://pub.elara.patract.io/westend"

  ],
};

export default config;
