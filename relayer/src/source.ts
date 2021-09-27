import { ApiPromise } from "@polkadot/api";
import { Observable } from "@polkadot/types/types";
import { U64 } from "@polkadot/types/primitive";
import { concatMap, mergeMap } from "rxjs/operators";
import { from } from 'rxjs';
import { Logger } from "pino";
import { Header, Hash, SignedBlock, Block } from "@polkadot/types/interfaces";

import { TxData, ParaHeadAndId } from "./types";
import { getParaHeadAndIdFromRecord, isRelevantRecord } from './utils'
import Parachain from "./parachain";

type SourceConstructorParams = {
  api: ApiPromise;
  chain: string;
  feedId: U64;
  parachainsMap: Map<string, Parachain>;
  logger: Logger;
};

class Source {
  private api: ApiPromise;
  private chain: string;
  private feedId: U64;
  private parachainsMap: Map<string, Parachain>;
  private logger: Logger;

  constructor(params: SourceConstructorParams) {
    this.api = params.api;
    this.chain = params.chain;
    this.feedId = params.feedId;
    this.parachainsMap = params.parachainsMap;
    this.logger = params.logger;
    this.getBlocksByHeader = this.getBlocksByHeader.bind(this);
  }

  private subscribeHeads(): Observable<Header> {
    return this.api.rx.rpc.chain.subscribeFinalizedHeads();
  }

  private getBlock(hash: Hash): Promise<SignedBlock> {
    return this.api.rpc.chain.getBlock(hash);
  }

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
          .map(getParaHeadAndIdFromRecord)
          .forEach((parablockData) => result.push(parablockData));
      }
    }

    return result;
  }

  private async getParablocks({ block }: SignedBlock) {
    const paraItems = await this.getParaHeadsAndIds(block);

    const parablockRequests = paraItems.map(async ({ paraHead, paraId }) => {
      const parachain = this.parachainsMap.get(paraId);
      if (!parachain) throw new Error(`Uknown paraId: ${paraId}`);

      const block = await parachain.fetchParaBlock(paraHead);

      // TODO: clarify how to handle this
      if (!block) {
        return
      }

      const header = this.api.createType("Header", block.block.header);

      const blockAsSignedBlock = this.api.createType("SignedBlock", {
        block: {
          // TODO: include extrinsics
          extrinsics: [],
          header,
        },
        justifications: block.justifications,
      });

      const hex = blockAsSignedBlock.toHex();

      const metadata = {
        hash: paraHead,
        number: this.api.createType("U32", header.number.toNumber())
      }

      // TODO: remove feedId hardcode
      return { block: hex, metadata, feedId: this.api.createType("U64", 2) };
    });

    return Promise.all(parablockRequests);
  }

  // TODO: should return observable instead of array
  private async getBlocksByHeader({ hash, number }: Header) {
    const block = await this.getBlock(hash);
    // TODO: fetch parablocks only if source chain has parachains
    const parablocks = await this.getParablocks(block);

    // TODO: check relay block and parablocks size
    // const size = Buffer.byteLength(block.toString());
    // console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);
    const hex = block.toHex();

    this.logger.info(`${this.chain} - finalized block hash: ${hash}`);
    this.logger.info(`Associated parablocks: ${parablocks.length}`);

    const metadata = {
      hash: hash,
      number: this.api.createType("U32", number.toNumber()),
    };

    const relayBlock = { feedId: this.feedId, block: hex, metadata };

    // TODO: add parablocks
    return from([relayBlock]);
  }

  subscribeBlocks(): Observable<TxData> {
    return this.subscribeHeads()
      .pipe(
        concatMap(this.getBlocksByHeader),
        mergeMap(x => x),
      );
  }
}

export default Source;
