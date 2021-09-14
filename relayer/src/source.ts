import { ApiPromise } from "@polkadot/api";
import { Header, Hash } from "@polkadot/types/interfaces";
import { Observable } from "@polkadot/types/types";
import { concatMap } from "rxjs/operators";

class Source {
  api: ApiPromise;
  chain: string;

  constructor({ api, chain }) {
    this.api = api;
    this.chain = chain;
  }

  subscribeHeads = (): Observable<Header> =>
    this.api.rx.rpc.chain.subscribeFinalizedHeads();

  getBlock = (hash: Hash) => this.api.rpc.chain.getBlock(hash);

  getBlockByHeader = async ({ hash }: Header): Promise<string> => {
    const block = await this.getBlock(hash);
    // TODO: should include size of headers?
    // TODO: what is the size limit?
    // TODO: check size - if too big reject
    const size = Buffer.byteLength(JSON.stringify(block));

    console.log(`Chain ${this.chain}: Finalized block hash: ${hash}`);
    console.log(`Chain ${this.chain}: Finalized block size: ${size / 1024} Kb`);

    // TODO: clarify how we identify chains
    return JSON.stringify({ ...block.toJSON(), chain: this.chain });
  };

  subscribeBlocks = (): Observable<string> =>
    this.subscribeHeads().pipe(concatMap(this.getBlockByHeader));
}

export default Source;
