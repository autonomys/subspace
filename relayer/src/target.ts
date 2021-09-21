import { ApiPromise } from "@polkadot/api";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { Observable } from "@polkadot/types/types";
import { merge } from "rxjs";
import { concatMap } from "rxjs/operators";

import { TxData } from "./types";

class Target {
  private api: ApiPromise;
  private signer: AddressOrPair;

  constructor({ api, signer }: { api: ApiPromise; signer: AddressOrPair }) {
    this.api = api;
    this.signer = signer;
  }

  private async sendBlockTx({ block, metadata }: TxData): Promise<void> {
    const unsub = await this.api.tx.feeds
      .put(block, metadata)
      // it is required to specify nonce, otherwise transaction within same block will be rejected
      // if nonce is -1 API will do the lookup for the right value
      // https://polkadot.js.org/docs/api/cookbook/tx/#how-do-i-take-the-pending-tx-pool-into-account-in-my-nonce
      .signAndSend(this.signer, { nonce: -1 }, (result) => {
        if (result.status.type === "InBlock") {
          // TODO: show module dispatch error
          const message = result.dispatchError
            ? "Transaction failed"
            : "Transaction successful";

          console.log(
            `${message}: https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944#/explorer/query/${result.status.asInBlock}`
          );

          unsub();
        }
      });
  }

  async createFeed(): Promise<void> {
    const unsub = await this.api.tx.feeds
      .createFeed()
      .signAndSend(this.signer, (result) => {
        if (result.status.type === "InBlock") {
          const feedCreatedEvent = result.events.find(
            ({ event }) => event.method === "FeedCreated"
          );

          if (feedCreatedEvent) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const feedId = (feedCreatedEvent.toJSON().event as any).data[0];

            // TODO: use feedId when create instances of Source
            console.log("New feed created: ", feedId);
          }

          unsub();
        }
      });
  }

  processBlocks = (subscriptions: Observable<TxData>[]): Observable<void> => {
    return merge(...subscriptions).pipe(concatMap(this.sendBlockTx.bind(this)));
  };
}

export default Target;
