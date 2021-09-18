import { ApiPromise } from "@polkadot/api";
import { Header, Hash, SignedBlock } from "@polkadot/types/interfaces";
import { EventRecord } from "@polkadot/types/interfaces/system";
import { Observable } from "@polkadot/types/types";
import { Text, U32 } from "@polkadot/types/primitive";
import { concatMap } from "rxjs/operators";

import { TxData } from "./types";

// TODO: consider moving to a separate utils module
// TODO: implement tests
const getParablockIds = ({ event }: EventRecord) => {
  // use 'any' because this is not typed array - element can be number, string or Record<string, unknown>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { paraHead, paraId } = (event.toJSON().data as Array<any>)[0]
    .descriptor;

  return { paraHead, paraId };
};

// TODO: more explicit function name
const isRelevantEventRecord =
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
  }

  private subscribeHeads = (): Observable<Header> =>
    this.api.rx.rpc.chain.subscribeFinalizedHeads();

  // TODO: should return Uint8Array instead of string
  private getBlock = (hash: Hash): Promise<SignedBlock> =>
    this.api.rpc.chain.getBlock(hash);

  private async getBlockEvents(signedBlock: SignedBlock) {
    const allRecords = await this.api.query.system.events.at(
      signedBlock.block.header.hash
    );
    // map between the extrinsics and events
    signedBlock.block.extrinsics.forEach(
      ({ method: { method, section } }, index) => {
        if (section == "paraInherent" && method == "enter") {
          const eventsData = allRecords
            .filter(isRelevantEventRecord(index))
            .map(getParablockIds);

          console.log(eventsData);
        }
      }
    );
  }

  private getBlockByHeader = async ({ hash }: Header): Promise<TxData> => {
    const block = await this.getBlock(hash);

    await this.getBlockEvents(block);
    // console.log(block.toJSON());
    // TODO: check relay block and parablocks size
    // const size = Buffer.byteLength(block);
    // get block events
    // get para_hashes
    // get parablocks

    console.log(`Chain ${this.chain}: Finalized block hash: ${hash}`);
    // console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);

    return { block: block.toString(), chainId: this.chainId };
  };

  subscribeBlocks = (): Observable<TxData> =>
    this.subscribeHeads().pipe(concatMap(this.getBlockByHeader));
}

export default Source;
