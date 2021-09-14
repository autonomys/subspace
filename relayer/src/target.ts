import { ApiPromise } from "@polkadot/api";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { Hash } from "@polkadot/types/interfaces";

class Target {
  api: ApiPromise;
  signer: AddressOrPair;

  constructor({ api, signer }) {
    this.api = api;
    this.signer = signer;
  }

  sendBlockTx = (block: string): Promise<Hash> =>
    this.api.tx.feeds
      .put(block)
      // it is required to specify nonce, otherwise transaction within same block will be rejected
      // if nonce is -1 API will do the lookup for the right value
      // https://polkadot.js.org/docs/api/cookbook/tx/#how-do-i-take-the-pending-tx-pool-into-account-in-my-nonce
      .signAndSend(this.signer, { nonce: -1 });
}

export default Target;
