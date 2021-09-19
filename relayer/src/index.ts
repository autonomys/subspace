import { ApiPromise, WsProvider } from "@polkadot/api";
import { RegistryTypes } from "@polkadot/types/types";
import { getAccount } from "./account";
import { loadConfig } from "./config";
import Source from "./source";
import Target from "./target";
import logger from "./logger";

const config = loadConfig();

// TODO: use typedefs from subspace.js
const types = {
  PutDataObject: "Vec<u8>",
  ChainId: "u32",
};

const createApi = async (url: string, types?: RegistryTypes) => {
  const provider = new WsProvider(url);
  const api = await ApiPromise.create({
    provider,
    types,
  });

  return api;
};

// TODO: remove IIFE when Eslint is updated to v8.0.0 (will support top-level await)
(async () => {
  const targetApi = await createApi(config.targetChainUrl, types);
  // use getAccount func because we cannot create keyring instance before API is instanciated
  const signer = getAccount(config.accountSeed);

  const target = new Target({ api: targetApi, signer, logger });

  const sources = await Promise.all(
    config.sourceChainUrls.map(async ({ url, chainId, parachains }) => {
      const api = await createApi(url);
      const chain = await api.rpc.system.chain();

      return new Source({
        api,
        chain,
        chainId: api.createType("u32", chainId),
        parachains,
        logger,
      });
    })
  );

  const blockSubscriptions = sources.map((source) => source.subscribeBlocks());

  target.processSubscriptions(blockSubscriptions).subscribe();
})();
