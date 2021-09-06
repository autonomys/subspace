import { ApiPromise, WsProvider } from "@polkadot/api";

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

  await api.rpc.chain.subscribeFinalizedHeads(async (lastHeader) => {
    const block = await api.rpc.chain.getBlock(lastHeader.hash);
    console.log(JSON.stringify(block));
  });
})();
