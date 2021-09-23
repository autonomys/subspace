import { ApiPromise, WsProvider } from "@polkadot/api";
import { RegistryTypes } from "@polkadot/types/types";

import { getAccount } from "./account";
import { loadConfig } from "./config";
import Source from "./source";
import Target from "./target";

const config = loadConfig();

// TODO: use typedefs from subspace.js
const types = {
  PutDataObject: "Vec<u8>",
  ObjectMetadata: {
    feedId: "FeedId",
    hash: "H256",
    number: "u32",
  },
  FeedId: "u64",
};

const createApi = async (url: string, types?: RegistryTypes) => {
  const provider = new WsProvider(url);
  const api = await ApiPromise.create({
    provider,
    types,
  });

  return api;
};

// TODO: consider moving to utils
const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const createFeeds = async (target: Target): Promise<number[]> => {
  const feedIds: number[] = [];

  for await (const _ of config.sourceChainUrls) {
    await target.createFeed(feedIds);
  }

  await sleep(15000);

  return feedIds;
};

// TODO: remove IIFE when Eslint is updated to v8.0.0 (will support top-level await)
(async () => {
  const targetApi = await createApi(config.targetChainUrl, types);
  // use getAccount func because we cannot create keyring instance before API is instanciated
  const signer = getAccount(config.accountSeed);

  const target = new Target({ api: targetApi, signer });

  const feedIds = await createFeeds(target);

  const sources = await Promise.all(
    config.sourceChainUrls.map(async ({ url }, index) => {
      const api = await createApi(url);
      const chain = await api.rpc.system.chain();
      const feedId = api.createType("u64", feedIds[index]);

      return new Source({
        api,
        chain,
        feedId,
      });
    })
  );

  const blockSubscriptions = sources.map((source) => source.subscribeBlocks());

  target.processBlocks(blockSubscriptions).subscribe();
})();
