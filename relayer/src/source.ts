import { ApiPromise } from "@polkadot/api";
import { Header, Hash, SignedBlock } from "@polkadot/types/interfaces";
import { Observable } from "@polkadot/types/types";
import { Text, U64 } from "@polkadot/types/primitive";
import { concatMap } from "rxjs/operators";

import { TxData } from "./types";

type SourceParams = {
  api: ApiPromise;
  chain: Text;
  feedId: U64;
};

class Source {
  private api: ApiPromise;
  private chain: Text;
  private feedId: U64;

  constructor({ api, chain, feedId }: SourceParams) {
    this.api = api;
    this.chain = chain;
    this.feedId = feedId;
  }

  private subscribeHeads = (): Observable<Header> =>
    this.api.rx.rpc.chain.subscribeFinalizedHeads();

  private getBlock = (hash: Hash): Promise<SignedBlock> =>
    this.api.rpc.chain.getBlock(hash);

  private getBlockByHeader = async ({
    hash,
    number,
  }: Header): Promise<TxData> => {
    const block = await this.getBlock(hash);
    const hex = block.toHex();
    const size = Buffer.byteLength(hex);

    console.log(`Chain ${this.chain}: Finalized block hash: ${hash}`);
    console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);

    const metadata = {
      hash,
      // TODO: probably there is a better way - investigate
      number: this.api.createType("U32", number.toNumber()),
    };

    return { feedId: this.feedId, block: hex, metadata };
  };

  subscribeBlocks = (): Observable<TxData> =>
    this.subscribeHeads().pipe(concatMap(this.getBlockByHeader));
}

export default Source;
