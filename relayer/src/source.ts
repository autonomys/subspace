import { ApiPromise } from "@polkadot/api";
import { Header, Hash, SignedBlock, Block } from "@polkadot/types/interfaces";
import { EventRecord } from "@polkadot/types/interfaces/system";
import { Observable } from "@polkadot/types/types";
import { Text, U32 } from "@polkadot/types/primitive";
import { concatMap } from "rxjs/operators";
import fetch from "node-fetch";

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
  parachains: Record<string, string>;
};

// TODO: better name
type ParablockIds = {
  paraId: string;
  paraHead: Hash;
};

class Source {
  private api: ApiPromise;
  private chain: Text;
  private chainId: U32;
  private parachains: Record<string, string>;

  constructor({ api, chain, chainId, parachains }: SourceParams) {
    this.api = api;
    this.chain = chain;
    this.chainId = chainId;
    this.parachains = parachains;
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
  private async getParablockIds(block: Block): Promise<ParablockIds[]> {
    const blockRecords = await this.api.query.system.events.at(
      block.header.hash
    );

    const parablockIds: ParablockIds[] = [];

    for (let index = 0; index < block.extrinsics.length; index++) {
      const { method } = block.extrinsics[index];

      if (method.section == "paraInherent" && method.method == "enter") {
        blockRecords
          .filter(isRelevantRecord(index))
          .map(getParablockIdsFromRecord)
          .forEach((parablockData) => parablockIds.push(parablockData));
      }
    }

    return parablockIds;
  }

  private async fetchBlock(url: string, hash: Hash): Promise<Block> {
    const options = {
      method: "post",
      body: JSON.stringify({
        id: 1,
        jsonrpc: "2.0",
        method: "chain_getBlock",
        params: [hash],
      }),
      headers: { "Content-Type": "application/json" },
    };

    return (
      fetch(url, options)
        .then((response) => response.json())
        .then(({ result }) => result)
        // TODO: better error handling
        .catch((error) => console.error(error))
    );
  }

  // TODO: add implementation
  private async getParablocks({ block }: SignedBlock) {
    const parablockIds = await this.getParablockIds(block);

    return Promise.all(
      parablockIds.map(({ paraHead, paraId }) => {
        // TODO: add handling for uknown paraId
        const paraUrl = this.parachains[paraId];

        return this.fetchBlock(paraUrl, paraHead);
      })
    );
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
