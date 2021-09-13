import { ApiPromise, WsProvider } from "@polkadot/api";
import { concatMap } from "rxjs/operators";

import { getAccount } from "./account";
import config from "./config";

// TODO: use typedefs from subspace.js
const types = {
  PutDataObject: "Vec<u8>",
};

// TODO: remove IIFE when Eslint is updated to v8.0.0 (will support top-level await)
(async () => {
  const sourceProvider = new WsProvider(config.sourceChainUrls[0]);
  const targetProvider = new WsProvider(config.targetChainUrl);

  const sourceApi = await ApiPromise.create({
    provider: sourceProvider,
  });

  const targetApi = await ApiPromise.create({
    provider: targetProvider,
    types,
  });

  // use getAccount func because we cannot create keyring instance before API is instanciated
  const signer = getAccount(config.accountSeed);

  // TODO: add old block processing

  sourceApi.rx.rpc.chain
    .subscribeFinalizedHeads()
    // use pipe and concatMap to process events one by one, otherwise multiple headers arrive simultaneously and there will be risk of having same nonce for multiple txs
    .pipe(
      concatMap(async ({ hash }) => {
        console.log(`Finalized block hash: ${hash}`);

        const block = await sourceApi.rpc.chain.getBlock(hash);

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
