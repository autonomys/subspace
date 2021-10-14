import { ApiPromise } from "@polkadot/api";
import { Subscription, EMPTY, catchError } from "rxjs";
import { takeWhile } from "rxjs/operators";
import { Logger } from "pino";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { KeyringPair } from "@polkadot/keyring/types";
import { ISubmittableResult } from "@polkadot/types/types";
import { EventRecord } from "@polkadot/types/interfaces";
import { U64 } from "@polkadot/types/primitive";

import { TxData } from "./types";
import State from './state';

// TODO: remove hardcoded url
const polkadotAppsUrl =
  "https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944#/explorer/query/";

interface TargetConstructorParams {
  api: ApiPromise;
  logger: Logger;
  state: State;
}

class Target {
  private readonly api: ApiPromise;
  private readonly logger: Logger;
  private readonly state: State;

  constructor({ api, logger, state }: TargetConstructorParams) {
    this.api = api;
    this.logger = logger;
    this.state = state;
    this.sendBlockTx = this.sendBlockTx.bind(this);
    this.logTxResult = this.logTxResult.bind(this);
  }

  private logTxResult({ status, events }: ISubmittableResult) {
    if (status.isInBlock) {
      const isExtrinsicFailed = events
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .filter(({ event }) => (event as any).isSystem)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .find(({ event }) => (event as any).asSystem.isExtrinsicFailed);

      if (isExtrinsicFailed) {
        this.logger.error("Extrinsic failed");
      }

      this.logger.info(
        `Transaction included: ${polkadotAppsUrl}${status.asInBlock}`
      );
    }
  }

  async sendBlockTx({ feedId, block, metadata, chain, signer }: TxData): Promise<Subscription> {
    this.logger.info(`Sending ${chain} block to feed: ${feedId}`);
    this.logger.debug(`Signer: ${(signer as KeyringPair).address}`);
    // metadata is stored as Vec<u8>
    // to decode: new TextDecoder().decode(new Uint8Array([...]))
    const metadataPayload = JSON.stringify(metadata);
    return (
      this.api.rx.tx.feeds
        .put(feedId, block, metadataPayload)
        // it is required to specify nonce, otherwise transaction within same block will be rejected
        // if nonce is -1 API will do the lookup for the right value
        // https://polkadot.js.org/docs/api/cookbook/tx/#how-do-i-take-the-pending-tx-pool-into-account-in-my-nonce
        .signAndSend(signer, { nonce: -1 }, Promise.resolve)
        .pipe(
          takeWhile(({ status }) => !status.isInBlock, true),
          catchError((error) => {
            this.logger.error(error);
            return EMPTY;
          }))
        .subscribe(this.logTxResult)
    );
  }

  private async sendCreateFeedTx(signer: AddressOrPair): Promise<U64> {
    this.logger.info(`Creating feed for signer ${(signer as KeyringPair).address}`);
    this.logger.debug(`Signer: ${(signer as KeyringPair).address}`);
    return new Promise((resolve) => {
      this.api.rx.tx.feeds
        .create()
        .signAndSend(signer, { nonce: -1 }, Promise.resolve)
        .pipe(
          takeWhile(({ status }) => !status.isInBlock, true),
          catchError((error) => {
            this.logger.error(error);
            return EMPTY;
          }))
        .subscribe((result) => {
          this.logTxResult(result);

          const feedCreatedEvent = result.events.find(
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ({ event }: EventRecord) => this.api.events.feeds.FeedCreated.is(event)
          );

          // TODO: handle case if transaction is included but no event found (may happe if API changes)
          if (feedCreatedEvent) {
            const { event } = feedCreatedEvent;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const feedId = (event as any).toJSON().data[0];
            this.logger.info(`New feed created: ${feedId}`);
            const feedIdAsU64 = this.api.createType('u64', feedId);
            resolve(feedIdAsU64);
          }
        });
    });
  }

  sendBalanceTx(from: AddressOrPair, to: AddressOrPair, amount: number): Promise<void> {
    const fromAddress = (from as KeyringPair).address;
    const toAddress = (to as KeyringPair).address;
    this.logger.info(`Sending balance ${amount} from ${fromAddress} to ${toAddress}`);
    return new Promise((resolve) => {
      this.api.rx.tx.balances
        .transfer(toAddress, amount * Math.pow(10, 12))
        .signAndSend(from, { nonce: -1 }, Promise.resolve)
        .pipe(
          takeWhile(({ status }) => !status.isInBlock, true),
          catchError((error) => {
            this.logger.error(error);
            return EMPTY;
          }))
        .subscribe((result) => {
          this.logTxResult(result);

          if (result.status.isInBlock) {
            resolve();
          }
        });
    });
  }

  async getFeedId(signer: AddressOrPair): Promise<U64> {
    const { address } = (signer as KeyringPair);
    this.logger.info(`Checking feed for ${address}`);

    const feedId = await this.state.getFeedIdByAddress(address);

    if (feedId) {
      // query chain state to check if there is an entry for this feedId
      const { isEmpty } = await this.api.query.feeds.feeds(feedId);

      // if it's not empty that means feedId exists both locally (in the feeds.json) and on the chain and we can re-use it
      if (!isEmpty) {
        const feedIdAsU64 = this.api.createType("U64", feedId);
        this.logger.info(`Feed already exists: ${feedIdAsU64}`);
        return feedIdAsU64;
      }

      // if feedId only exists locally, but not on the chain - we have to create a new one
      this.logger.error('Feed does not exist on the chain');
    }

    const newFeedId = await this.sendCreateFeedTx(signer);

    await this.state.saveFeedId(address, newFeedId);

    return newFeedId;
  }
}

export default Target;
