import { ApiPromise } from "@polkadot/api";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { ISubmittableResult, Observable } from "@polkadot/types/types";
import { EventRecord } from "@polkadot/types/interfaces";
import { U64 } from "@polkadot/types/primitive";
import { merge, Subscription } from "rxjs";
import { concatMap, take } from "rxjs/operators";

import { TxData } from "./types";

const polkadotAppsUrl =
  "https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944#/explorer/query/";

class Target {
  private api: ApiPromise;
  private signer: AddressOrPair;

  constructor({ api, signer }: { api: ApiPromise; signer: AddressOrPair }) {
    this.api = api;
    this.signer = signer;
  }

  private logTxResult({ status, events }: ISubmittableResult) {
    if (status.isInBlock) {
      const isExtrinsicFailed = events
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .filter(({ event }) => (event as any).isSystem)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .find(({ event }) => (event as any).asSystem.isExtrinsicFailed);

      if (isExtrinsicFailed) {
        console.error("Extrinsic failed");
      }

      console.log(
        `Transaction included: ${polkadotAppsUrl}${status.asInBlock}`
      );
    }
  }

  // TODO: signer should be proxy account per feed
  private async sendBlockTx({ block, metadata }: TxData) {
    return (
      this.api.rx.tx.feeds
        .put(block, metadata)
        // it is required to specify nonce, otherwise transaction within same block will be rejected
        // if nonce is -1 API will do the lookup for the right value
        // https://polkadot.js.org/docs/api/cookbook/tx/#how-do-i-take-the-pending-tx-pool-into-account-in-my-nonce
        .signAndSend(this.signer, { nonce: -1 }, Promise.resolve)
        .pipe(take(2)) // we only need to subscribe until second status - IN BLOCK
        .subscribe(this.logTxResult)
    );
  }

  // TODO: signer should be proxy account per feed
  // TODO: think about re-using existing feedIds instead of creating
  async sendCreateFeedTx(): Promise<U64> {
    console.log("Creating feed for signer X");
    return new Promise((resolve) => {
      this.api.rx.tx.feeds
        .create()
        .signAndSend(this.signer, { nonce: -1 }, Promise.resolve)
        .pipe(take(2)) // we only need to subscribe until second status - IN BLOCK
        .subscribe((result) => {
          this.logTxResult(result);

          const feedCreatedEvent = result.events.find(
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ({ event }: EventRecord) => (event as any)?.isFeeds
          );

          if (feedCreatedEvent) {
            const { event } = feedCreatedEvent;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const feedId = (event as any).asFeeds.asFeedCreated.toJSON()[0];

            console.log("New feed created: ", feedId);
            const feedIdAsU64 = this.api.createType('u64', feedId);
            resolve(feedIdAsU64);
          }
        });
    });
  }

  processBlocks = (
    subscriptions: Observable<TxData>[]
  ): Observable<Subscription> => {
    return merge(...subscriptions).pipe(concatMap(this.sendBlockTx.bind(this)));
  };
}

export default Target;
