import { ApiPromise } from "@polkadot/api";
import { Header, Hash } from "@polkadot/types/interfaces";
import { Observable } from "@polkadot/types/types";

class Source {
  api: ApiPromise;

  constructor({ api }) {
    this.api = api;
  }

  subscribeHeads = (): Observable<Header> =>
    this.api.rx.rpc.chain.subscribeFinalizedHeads();

  getChain = () => this.api.rpc.system.chain();

  getBlock = (hash: Hash) => this.api.rpc.chain.getBlock(hash);

  getBlockByHeader = async ({ hash }: Header): Promise<string> => {
    const chain = await this.getChain();
    const block = await this.getBlock(hash);
    // TODO: should include size of headers?
    // TODO: what is the size limit?
    // TODO: check size - if too big reject
    const size = Buffer.byteLength(JSON.stringify(block));

    console.log(`Chain ${chain}: Finalized block hash: ${hash}`);
    console.log(`Chain ${chain}: Finalized block size: ${size / 1024} Kb`);

    // TODO: clarify how we identify chains
    return JSON.stringify({ ...block.toJSON(), chain });
  };
}

export default Source;
