import { ApiPromise, WsProvider } from "@polkadot/api";
import { Header } from "@polkadot/types/interfaces";
import { RegistryTypes } from "@polkadot/types/types";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { merge } from "rxjs";
import { concatMap, map } from "rxjs/operators";

import { getAccount } from "./account";
import config from "./config";

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

const createGetBlockByHeader =
  (api: ApiPromise) =>
  async ({ hash }: Header) => {
    const chain = await api.rpc.system.chain();
    const block = await api.rpc.chain.getBlock(hash);
    // TODO: should include size of headers?
    // TODO: what is the size limit?
    // TODO: check size - if too big reject
    const size = Buffer.byteLength(JSON.stringify(block));

    console.log(`Chain ${chain}: Finalized block hash: ${hash}`);
    console.log(`Chain ${chain}: Finalized block size: ${size / 1024} Kb`);

    // TODO: clarify how we identify chains
    return JSON.stringify({ ...block.toJSON(), chain });
  };

const createSendBlockTx =
  (api: ApiPromise, signer: AddressOrPair) => async (block: string) => {
    const txHash = await api.tx.feeds
      .put(block)
      // it is required to specify nonce, otherwise transaction within same block will be rejected
      // if nonce is -1 API will do the lookup for the right value
      // https://polkadot.js.org/docs/api/cookbook/tx/#how-do-i-take-the-pending-tx-pool-into-account-in-my-nonce
      .signAndSend(signer, { nonce: -1 });

    return txHash;
  };

// TODO: remove IIFE when Eslint is updated to v8.0.0 (will support top-level await)
(async () => {
  const targetApi = await createApi(config.targetChainUrl, types);
  const sourceApis = await Promise.all(
    config.sourceChainUrls.map((url) => createApi(url))
  );

  // use getAccount func because we cannot create keyring instance before API is instanciated
  const signer = getAccount(config.accountSeed);

  const blockSubscriptions = sourceApis.map((api) => {
    const getBlockByHeader = createGetBlockByHeader(api);
    // use pipe and concatMap to process events one by one
    return api.rx.rpc.chain
      .subscribeFinalizedHeads()
      .pipe(concatMap(getBlockByHeader));
  });

  const sendBlockTx = createSendBlockTx(targetApi, signer);

  merge(...blockSubscriptions)
    // use pipe and concatMap to process events one by one
    .pipe(
      concatMap(sendBlockTx),
      map((txHash) => {
        // TODO: clarify if we need to know which tx corresponds to which chain
        console.log(`Transaction sent: ${txHash}`);
      })
    )
    .subscribe();
})();
