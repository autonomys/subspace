import { ApiPromise } from "@polkadot/api";
import { Header, Hash, SignedBlock, Block } from "@polkadot/types/interfaces";
import { EventRecord } from "@polkadot/types/interfaces/system";
import { Observable } from "@polkadot/types/types";
import { Text, U32 } from "@polkadot/types/primitive";
import { concatMap } from "rxjs/operators";

import { TxData } from "./types";

// TODO: consider moving to a separate utils module
// TODO: implement tests
const getParablockIdsFromRecord = ({ event }: EventRecord) => {
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

type SourceParams = {
  api: ApiPromise;
  chain: Text;
  chainId: U32;
};

class Source {
  private api: ApiPromise;
  private chain: Text;
  private chainId: U32;

  constructor({ api, chain, chainId }: SourceParams) {
    this.api = api;
    this.chain = chain;
    this.chainId = chainId;
    this.getBlocksByRelayHeader = this.getBlocksByRelayHeader.bind(this);
  }

  private subscribeHeads(): Observable<Header> {
    return this.api.rx.rpc.chain.subscribeFinalizedHeads();
  }

  // TODO: should return Uint8Array instead of string
  private getBlock(hash: Hash): Promise<SignedBlock> {
    return this.api.rpc.chain.getBlock(hash);
  }

  // TODO: refactor and implement tests
  private async getParablockIds(block: Block) {
    const blockRecords = await this.api.query.system.events.at(
      block.header.hash
    );

    return block.extrinsics
      .map(({ method: { method, section } }, index) => {
        if (section == "paraInherent" && method == "enter") {
          return blockRecords
            .filter(isRelevantRecord(index))
            .map(getParablockIdsFromRecord);
        }

        return;
      })
      .filter(Boolean)[0];
  }

  // TODO: add implementation
  private async getParablocks({ block }: SignedBlock) {
    const parablockIds = await this.getParablockIds(block);
    const blocks = parablockIds?.map(({ paraHead, paraId }) => {
      console.log({ paraHead, paraId });

      // get chain api by paraId
      // get block from api by hash

      return;
    });

    return blocks;
  }

  private async getBlocksByRelayHeader({ hash }: Header): Promise<TxData[]> {
    const block = await this.getBlock(hash);
    const parablocks = await this.getParablocks(block);
    console.log({ parablocks });
    // TODO: check relay block and parablocks size
    // const size = Buffer.byteLength(block.toString());

    console.log(`Chain ${this.chain}: Finalized block hash: ${hash}`);
    // console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);

    // TODO: return parablocks
    return [{ block: block.toString(), chainId: this.chainId }];
  }

  subscribeBlocks(): Observable<TxData[]> {
    return this.subscribeHeads().pipe(concatMap(this.getBlocksByRelayHeader));
  }
}

export default Source;
