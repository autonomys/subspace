import * as dotenv from "dotenv";

dotenv.config();

const config = {
  accountSeed: process.env.ACCOUNT_SEED,
  targetChainUrl: process.env.TARGET_CHAIN_URL,
  sourceChainUrls: [process.env.SOURCE_CHAIN_URL],
};

export default config;
