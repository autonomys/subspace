import { ApiPromise } from "@polkadot/api";
import { concatMap } from "rxjs/operators";
import { Logger } from "pino";
import { Header, Hash, SignedBlock, Block } from "@polkadot/types/interfaces";
import { EventRecord } from "@polkadot/types/interfaces/system";
import { Observable } from "@polkadot/types/types";
import { Text, U32 } from "@polkadot/types/primitive";

import { TxData } from "./types";
import { FetchBlockFunc } from "./rpc";

// TODO: consider moving to a separate utils module
// TODO: implement tests
const getParaHeadAndIdFromRecord = ({ event }: EventRecord) => {
  // use 'any' because this is not typed array - element can be number, string or Record<string, unknown>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { paraHead, paraId } = (event.toJSON().data as Array<any>)[0]
    .descriptor;

  return { paraHead, paraId };
};

// TODO: more explicit function name
const isRelevantRecord =
  (index: number) =>
  ({ phase, event }: EventRecord) => {
    return (
      // filter the specific events based on the phase and then the
      // index of our extrinsic in the block
      phase.isApplyExtrinsic &&
      phase.asApplyExtrinsic.eq(index) &&
      event.section == "paraInclusion" &&
      event.method == "CandidateIncluded"
    );
  };

type SourceConstructorParams = {
  api: ApiPromise;
  chain: Text;
  chainId: U32;
  parachains: Record<string, string>;
  logger: Logger;
  fetchBlock: FetchBlockFunc;
};

type ParaHeadAndId = {
  paraId: string;
  paraHead: Hash;
};

class Source {
  private api: ApiPromise;
  private chain: Text;
  private chainId: U32;
  private parachains: Record<string, string>;
  private logger: Logger;
  private fetchBlock: FetchBlockFunc;

  constructor({
    api,
    chain,
    chainId,
    parachains,
    logger,
    fetchBlock,
  }: SourceConstructorParams) {
    this.api = api;
    this.chain = chain;
    this.chainId = chainId;
    this.parachains = parachains;
    this.logger = logger;
    this.fetchBlock = fetchBlock;
    this.getBlocksByHeader = this.getBlocksByHeader.bind(this);
  }

  private subscribeHeads(): Observable<Header> {
    return this.api.rx.rpc.chain.subscribeFinalizedHeads();
  }

  // TODO: should return Uint8Array instead of string
  private getBlock(hash: Hash): Promise<SignedBlock> {
    return this.api.rpc.chain.getBlock(hash);
  }

  // TODO: refactor and implement tests
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

  // TODO: add implementation
  private async getParablocks({ block }: SignedBlock) {
    const paraItems = await this.getParaHeadsAndIds(block);

    return Promise.all(
      paraItems.map(({ paraHead, paraId }) => {
        const paraUrl = this.parachains[paraId];

        if (!paraUrl) throw new Error(`Uknown paraId: ${paraId}`);

        // TODO: return { block, chainId }
        return this.fetchBlock(paraUrl, paraHead);
      })
    );
  }

  private async getBlocksByHeader({ hash }: Header): Promise<TxData[]> {
    const block = await this.getBlock(hash);
    const parablocks = await this.getParablocks(block);

    // TODO: check relay block and parablocks size
    // const size = Buffer.byteLength(block.toString());
    // console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);

    this.logger.info(
      `Relay chain ${this.chain} - finalized block hash: ${hash}`
    );
    this.logger.info(`Associated parablocks: ${parablocks.length}`);
    // this.logger.info(parablocks);

    // TODO: return parablocks
    return [{ block: block.toString(), chainId: this.chainId }];
  }

  subscribeBlocks(): Observable<TxData[]> {
    return this.subscribeHeads().pipe(concatMap(this.getBlocksByHeader));
  }
}

export default Source;
