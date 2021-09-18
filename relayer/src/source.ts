import { ApiPromise } from "@polkadot/api";
import { Header, Hash, SignedBlock } from "@polkadot/types/interfaces";
import { Observable } from "@polkadot/types/types";
import { Text } from "@polkadot/types/primitive";
import { concatMap } from "rxjs/operators";

class Source {
  private api: ApiPromise;
  private chain: Text;

  constructor({ api, chain }: { api: ApiPromise; chain: Text }) {
    this.api = api;
    this.chain = chain;
  }

  private subscribeHeads = (): Observable<Header> =>
    this.api.rx.rpc.chain.subscribeFinalizedHeads();

  private getBlock = (hash: Hash): Promise<SignedBlock> =>
    this.api.rpc.chain.getBlock(hash);

  private getBlockByHeader = async ({ hash }: Header): Promise<string> => {
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
