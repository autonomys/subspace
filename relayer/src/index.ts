import { ApiPromise, WsProvider } from "@polkadot/api";
import { merge } from "rxjs";
import { getAccount } from "./account";
import config from "./config";
import Source from "./source";
import Target from "./target";
import logger from "./logger";
import { createParachainsMap } from './utils';

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
  const target = new Target({ api: targetApi, logger });

  const sources = await Promise.all(
    config.sourceChainUrls.map(async ({ url, parachains }, index) => {
      const api = await createApi(url);
      const chain = await api.rpc.system.chain();
      const signer = getAccount(config.sourceChainUrls[index].signerSeed);
      const feedId = await target.sendCreateFeedTx(signer);
      const parachainsMap = await createParachainsMap(target, parachains);

      return new Source({
        api,
        chain: chain.toString(),
        parachainsMap,
        logger,
        feedId,
        signer,
      });
    })
  );

  const blockSubscriptions = merge(...sources.map((source) => source.subscribeBlocks()));

  target.processSubscriptions(blockSubscriptions).subscribe();
})();
