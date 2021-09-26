import { ApiPromise, WsProvider } from "@polkadot/api";

import { getAccount } from "./account";
import { loadConfig } from "./config";
import Source from "./source";
import Target from "./target";

const config = loadConfig();

const createApi = async (url: string) => {
  const provider = new WsProvider(url);
  const api = await ApiPromise.create({
    provider,
  });

  return api;
};

// TODO: remove IIFE when Eslint is updated to v8.0.0 (will support top-level await)
(async () => {
  const targetApi = await createApi(config.targetChainUrl);
  // use getAccount func because we cannot create keyring instance before API is instanciated
  const signer = getAccount(config.accountSeed);

  const target = new Target({ api: targetApi, signer });


  const sources = await Promise.all(
    config.sourceChainUrls.map(async ({ url }) => {
      const api = await createApi(url);
      const chain = await api.rpc.system.chain();
      const feedId = await target.sendCreateFeedTx();

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
