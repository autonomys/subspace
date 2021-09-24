import fetch from "node-fetch";
import { Hash, SignedBlock } from "@polkadot/types/interfaces";

export type FetchParaBlockFunc = (url: string, hash: Hash) => Promise<SignedBlock>;

export const fetchParaBlock = async (
  url: string,
  hash: Hash
): Promise<SignedBlock> => {
  const options = {
    method: "post",
    body: JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method: "chain_getBlock",
      params: [hash],
    }),
    headers: { "Content-Type": "application/json" },
  };

  return (
    fetch(url, options)
      .then((response) => response.json())
      .then(({ result }) => result)
      // TODO: better error handling
      .catch((error) => console.error(error))
  );
};
