import { ApiPromise } from "@polkadot/api";
import { Observable } from "@polkadot/types/types";
import { U64 } from "@polkadot/types/primitive";
import { Header, Hash, SignedBlock, Block } from "@polkadot/types/interfaces";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { BN } from '@polkadot/util';
import { concatMap, take, map, tap, concatAll } from "rxjs/operators";
import { from, merge, EMPTY } from 'rxjs';
import { Logger } from "pino";

import { ParaHeadAndId, TxData, ChainName } from "./types";
import { getParaHeadAndIdFromEvent, isRelevantRecord } from './utils';
import Parachain from "./parachain";
import { saveLastProcessedBlock } from './state';

interface SourceConstructorParams {
  api: ApiPromise;
  chain: ChainName;
  feedId: U64;
  parachainsMap: Map<string, Parachain>;
  logger: Logger;
  signer: AddressOrPair;
}

interface TxDataInput {
  block: string;
  number: BN;
  hash: Hash;
  feedId: U64;
  chain: ChainName;
  signer: AddressOrPair;
}

class Source {
  private readonly api: ApiPromise;
  private readonly chain: ChainName;
  private readonly feedId: U64;
  private readonly parachainsMap: Map<string, Parachain>;
  private readonly logger: Logger;
  public readonly signer: AddressOrPair;

  constructor(params: SourceConstructorParams) {
    this.api = params.api;
    this.chain = params.chain;
    this.feedId = params.feedId;
    this.parachainsMap = params.parachainsMap;
    this.logger = params.logger;
    this.signer = params.signer;
    this.getBlocksByHash = this.getBlocksByHash.bind(this);
    this.getParablocks = this.getParablocks.bind(this);
  }

  private subscribeHeads(): Observable<Header> {
    return this.api.rx.rpc.chain.subscribeFinalizedHeads();
  }

  private getBlock(hash: Hash): Observable<SignedBlock> {
    return this.api.rx.rpc.chain.getBlock(hash).pipe(take(1));
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
              return this.addBlockTxData({
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

  private addBlockTxData({ block, number, hash, feedId, chain, signer }: TxDataInput): TxData {
    return {
      feedId,
      block,
      chain,
      signer,
      metadata: {
        hash,
        number,
      },
    };
  }

  private getBlocksByHash(hash: Hash): Observable<TxData> {
    const relayBlock = this.getBlock(hash);
    const parablocks = relayBlock.pipe(concatMap(this.getParablocks));

    const relayBlockWithMetadata = relayBlock
      .pipe(map(({ block }) => {
        const blockStr = block.toString();
        const number = block.header.number.toBn();
        return this.addBlockTxData({
          block: blockStr,
          number,
          hash,
          feedId: this.feedId,
          chain: this.chain,
          signer: this.signer
        });
      }))
      .pipe(tap(({ metadata }) => saveLastProcessedBlock(this.chain, metadata.number)));

    // TODO: check relay block and parablocks size
    // const size = Buffer.byteLength(block.toString());
    // console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);

    this.logger.info(`${this.chain} - finalized block hash: ${hash}`);

    return merge(relayBlockWithMetadata, parablocks);
  }

  subscribeBlocks(): Observable<TxData> {
    return this.subscribeHeads().pipe(concatMap(({ hash }) => this.getBlocksByHash(hash)));
  }
}

export default Source;
