import { ApiPromise, WsProvider } from "@polkadot/api";
import { RegistryTypes } from "@polkadot/types/types";
import { merge } from "rxjs";
import { concatMap, map } from "rxjs/operators";

import { getAccount } from "./account";
import config from "./config";
import Source from "./source";
import Target from "./target";

// TODO: use typedefs from subspace.js
const types = {
  PutDataObject: "Vec<u8>",
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

  const target = new Target({ api: targetApi, signer });

  const sources = await Promise.all(
    config.sourceChainUrls.map(async (url) => {
      const api = await createApi(url);

      return new Source({ api });
    })
  );

  const blockSubscriptions = sources.map((source) =>
    source.subscribeHeads().pipe(concatMap(source.getBlockByHeader))
  );

  merge(...blockSubscriptions)
    .pipe(
      concatMap(target.sendBlockTx),
      map((txHash) => {
        // TODO: clarify if we need to know which tx corresponds to which chain
        console.log(`Transaction sent: ${txHash}`);
      })
    )
    .subscribe();
})();
