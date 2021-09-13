import { ApiPromise, WsProvider } from "@polkadot/api";
import { merge } from "rxjs";
import { concatMap, map } from "rxjs/operators";

import { getAccount } from "./account";
import config from "./config";

// TODO: use typedefs from subspace.js
const types = {
  PutDataObject: "Vec<u8>",
};

// TODO: remove IIFE when Eslint is updated to v8.0.0 (will support top-level await)
(async () => {
  const targetProvider = new WsProvider(config.targetChainUrl);

  const sourceApis = await Promise.all(
    config.sourceChainUrls.map(async (url) => {
      const provider = new WsProvider(url);
      const api = await ApiPromise.create({
        provider,
      });

      return api;
    })
  );

  const targetApi = await ApiPromise.create({
    provider: targetProvider,
    types,
  });

  // use getAccount func because we cannot create keyring instance before API is instanciated
  const signer = getAccount(config.accountSeed);

  // TODO: add old block processing
  const observables = sourceApis.map((api) => {
    return api.rx.rpc.chain.subscribeFinalizedHeads().pipe(
      map(async ({ hash }) => {
        const chain = await api.rpc.system.chain();
        const block = await api.rpc.chain.getBlock(hash);
        console.log(`Chain ${chain}: Finalized block hash: ${hash}`);
        return block;
      })
    );
  });

  merge(...observables)
    // use pipe and concatMap to process events one by one, otherwise multiple headers arrive simultaneously and there will be risk of having same nonce for multiple txs
    .pipe(
      concatMap(async (block) => {
        // TODO: check size - if too big reject
        const txHash = await targetApi.tx.feeds
          .put(block.toString())
          // it is required to specify nonce, otherwise transaction within same block will be rejected
          // if nonce is -1 API will do the lookup for the right value
          // https://polkadot.js.org/docs/api/cookbook/tx/#how-do-i-take-the-pending-tx-pool-into-account-in-my-nonce
          .signAndSend(signer, { nonce: -1 });
        console.log(`Transaction sent: ${txHash}`);
      })
    )
    .subscribe();
})();
