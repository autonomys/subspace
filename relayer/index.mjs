import { ApiPromise, WsProvider } from "@polkadot/api";
import { getAccount } from "./account.mjs";
// TODO: ensure we're connecting to archive node
// TODO: replace hardcoded value with configurable
const wsProvider = new WsProvider("ws://127.0.0.1:9944");

// TODO: use typedefs from subspace.js
const types = {
  PutDataObject: "Vec<u8>",
};

// TODO: remove IIFE when Eslint is updated to v8.0.0 (will support top-level await)
(async () => {
  const api = await ApiPromise.create({
    provider: wsProvider,
    types,
  });

  // use getAccount func because we cannot create keyring instance before API is instanciated
  // TODO: replace hardcoded seed with configurable
  const signer = getAccount("//Alice");

  // TODO: add old block processing

  await api.rpc.chain.subscribeFinalizedHeads(async (lastHeader) => {
    const block = await api.rpc.chain.getBlock(lastHeader.hash);

    // TODO: replace templateModule with feeds
    const txHash = await api.tx.templateModule
      .put(block.toString())
      .signAndSend(signer);

    console.log(txHash.toString());
  });
})();
