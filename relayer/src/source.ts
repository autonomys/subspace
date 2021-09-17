import { ApiPromise } from "@polkadot/api";
import { Header, Hash } from "@polkadot/types/interfaces";
import { Observable } from "@polkadot/types/types";
import { Text, U32 } from "@polkadot/types/primitive";
import { concatMap } from "rxjs/operators";

import { TxData } from "./types";

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
  private getBlock = (hash: Hash): Promise<string> =>
    this.api.rpc.chain.getBlock(hash).then((block) => block.toString());

  private getBlockByHeader = async ({ hash }: Header): Promise<TxData> => {
    const block = await this.getBlock(hash);
    const size = Buffer.byteLength(block);

    console.log(`Chain ${this.chain}: Finalized block hash: ${hash}`);
    console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);

    return { block, chainId: this.chainId };
  };

  subscribeBlocks = (): Observable<TxData> =>
    this.subscribeHeads().pipe(concatMap(this.getBlockByHeader));
}

export default Source;
