import { ApiPromise } from "@polkadot/api";
import { Observable } from "@polkadot/types/types";
import { U64 } from "@polkadot/types/primitive";
import { Header, Hash, SignedBlock, Block } from "@polkadot/types/interfaces";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { concatMap, map, tap, concatAll, first, expand } from "rxjs/operators";
import { from, merge, EMPTY, defer, catchError } from 'rxjs';
import { Logger } from "pino";
import * as BN from 'bn.js';

import { ParaHeadAndId, TxData, ChainName } from "./types";
import { getParaHeadAndIdFromEvent, isRelevantRecord, toBlockTxData } from './utils';
import Parachain from "./parachain";
import State from './state';

interface SourceConstructorParams {
  api: ApiPromise;
  chain: ChainName;
  feedId: U64;
  parachainsMap: Map<string, Parachain>;
  logger: Logger;
  signer: AddressOrPair;
  state: State;
}

class Source {
  private readonly api: ApiPromise;
  private readonly chain: ChainName;
  private readonly feedId: U64;
  private readonly parachainsMap: Map<string, Parachain>;
  private readonly logger: Logger;
  private readonly state: State;
  public readonly signer: AddressOrPair;

  constructor(params: SourceConstructorParams) {
    this.api = params.api;
    this.chain = params.chain;
    this.feedId = params.feedId;
    this.parachainsMap = params.parachainsMap;
    this.logger = params.logger;
    this.signer = params.signer;
    this.state = params.state;
    this.getBlocksByHash = this.getBlocksByHash.bind(this);
    this.getParablocks = this.getParablocks.bind(this);
    this.getLastProcessedBlockNumber = this.getLastProcessedBlockNumber.bind(this);
    this.getFinalizedHeader = this.getFinalizedHeader.bind(this);
  }

  private subscribeHeads(): Observable<Header> {
    return this.api.rx.rpc.chain.subscribeFinalizedHeads();
  }

  private getBlock(hash: Hash): Observable<SignedBlock> {
    return this.api.rx.rpc.chain.getBlock(hash).pipe(first());
  }

  private async getFinalizedHeader(): Promise<Header> {
    const finalizedHash = await this.api.rpc.chain.getFinalizedHead();
    const finalizedHeader = await this.api.rpc.chain.getHeader(finalizedHash);
    return finalizedHeader;
  }

  private async getLastProcessedBlockNumber(): Promise<BN | undefined> {
    const number = await this.state.getLastProcessedBlockByName(this.chain);
    this.logger.debug(`Last processed block number in state: ${number}`);
    return number;
  }

  resyncBlocks(): Observable<TxData> {
    this.logger.info('Start queuing resync blocks');
    return defer(this.getLastProcessedBlockNumber)
      .pipe(expand(async (blockNumber) => {
        if (!blockNumber) return new BN(0);
        const blockNumberAsBn = this.api.createType("BlockNumber", blockNumber).toBn();
        this.logger.debug(`Last processed block: ${blockNumberAsBn.toString()}`);
        const nextBlockNumber = blockNumberAsBn.add(new BN(1));
        const { number: finalizedNumber } = await this.getFinalizedHeader();
        const diff = finalizedNumber.toBn().sub(nextBlockNumber);
        this.logger.info(`Processing blocks from ${nextBlockNumber.toString()}`);
        this.logger.debug(`Finalized block: ${finalizedNumber.toString()}`);
        this.logger.debug(`Diff: ${diff}`);

        // TODO: currently this works, but there might be more elegant way to terminate
        if (diff.isZero()) throw new Error("Queuing resync blocks is done");

        return nextBlockNumber;
      }))
      .pipe(
        catchError((error) => {
          this.logger.error(error);
          return EMPTY;
        }))
      // get block hash for each block number
      .pipe(concatMap((blockNumber) => this.api.rx.rpc.chain.getBlockHash(blockNumber)
        .pipe(tap((blockHash) => this.logger.debug(`${blockNumber} : ${blockHash}`)))))
      // process blocks by source chain block hash
      .pipe(concatMap(this.getBlocksByHash));
  }

  // TODO: refactor to return Observable<ParaHeadAndId>
  private async getParaHeadsAndIds(block: Block): Promise<ParaHeadAndId[]> {
    const blockRecords = await this.api.query.system.events.at(
      block.header.hash
    );

    const result: ParaHeadAndId[] = [];

    for (let index = 0; index < block.extrinsics.length; index++) {
      const { method } = block.extrinsics[index];

      if (method.section == "paraInherent" && method.method == "enter") {
        blockRecords
          .filter(isRelevantRecord(index))
          .map(({ event }) => getParaHeadAndIdFromEvent(event))
          .forEach((parablockData) => result.push(parablockData));
      }
    }

    this.logger.info(`Associated parablocks: ${result.length}`);
    this.logger.debug(`ParaIds: ${result.map(({ paraId }) => paraId).join(", ")}`);

    return result;
  }

  // TODO: add logging for individual parablocks
  getParablocks({ block }: SignedBlock): Observable<TxData> {
    return from(this.getParaHeadsAndIds(block))
      // print extracted para heads and ids
      .pipe(tap((paraHeadsAndIds) => paraHeadsAndIds
        .forEach(paraItem => this.logger.debug(`Extracted para head and id: ${JSON.stringify(paraItem)}`))))
      // converts Observable<ParaHeadAndId[]> to Observable<ParaHeadAndId>
      .pipe(concatAll())
      .pipe(
        concatMap(({ paraId, paraHead }) => {
          const parachain = this.parachainsMap.get(paraId);

          // skip parachains that are not included in config
          if (!parachain) {
            this.logger.error(`Uknown paraId: ${paraId}`);
            return EMPTY;
          }

          const { feedId, chain, signer } = parachain;

          return parachain.fetchParaBlock(paraHead)
            .pipe(map(({ block }) => {
              const blockStr = JSON.stringify(block);
              const number = this.api.createType("BlockNumber", block.header.number).toBn();
              return toBlockTxData({
                block: blockStr,
                number,
                hash: paraHead,
                feedId,
                chain,
                signer
              });
            }));
        })
      );
  }

  private getBlocksByHash(hash: Hash): Observable<TxData> {
    const relayBlock = this.getBlock(hash);
    const parablocks = relayBlock.pipe(concatMap(this.getParablocks));

    const relayBlockWithMetadata = relayBlock
      .pipe(map(({ block }) => {
        const blockStr = block.toString();
        const number = block.header.number.toBn();

        this.logger.info(`${this.chain} - processing block: ${hash}, height: ${number.toString()}`);

        return toBlockTxData({
          block: blockStr,
          number,
          hash,
          feedId: this.feedId,
          chain: this.chain,
          signer: this.signer
        });
      }))
      // TODO: consider saving last processed block after transaction is sent (move to Target)
      .pipe(tap(({ metadata }) => this.state.saveLastProcessedBlock(this.chain, metadata.number)));

    // TODO: check relay block and parablocks size
    // const size = Buffer.byteLength(block.toString());
    // console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);

    return merge(relayBlockWithMetadata, parablocks);
  }

  subscribeNewBlocks(): Observable<TxData> {
    return this.subscribeHeads().pipe(concatMap(({ hash }) => this.getBlocksByHash(hash)));
  }
}

export default Source;
