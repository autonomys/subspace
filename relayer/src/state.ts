import * as fsp from "fs/promises";
import { BN } from '@polkadot/util';

import { ChainName } from './types';

// TODO: consider providing fs methods to constructor
class State {
    lastBlockPath: string;
    feedsPath: string;

    constructor({ folder }: { folder: string; }) {
        this.lastBlockPath = `${folder}/last_processed_block.json`;
        this.feedsPath = `${folder}/feeds.json`;
    }

    async saveLastProcessedBlock(chain: ChainName, number: BN): Promise<void> {
        const file = await fsp.readFile(this.lastBlockPath, 'utf8');
        const lastProcessedBlockRecord = JSON.parse(file);

        lastProcessedBlockRecord[chain] = number;

        await fsp.writeFile(this.lastBlockPath, JSON.stringify(lastProcessedBlockRecord, null, 4));
    }

    async getLastProcessedBlockByName(chain: ChainName): Promise<BN | undefined> {
        const file = await fsp.readFile(this.lastBlockPath, 'utf8');
        const lastProcessedBlockRecord = JSON.parse(file);

        return lastProcessedBlockRecord[chain];
    }

    async getFeedIdByAddress(address: string): Promise<string> {
        const file = await fsp.readFile(this.feedsPath, 'utf8');
        const feeds = JSON.parse(file);

        return feeds[address];
    }

    async saveFeedId(address: string, feedId: BN): Promise<void> {
        const file = await fsp.readFile(this.feedsPath, 'utf8');
        const feeds = JSON.parse(file);

        feeds[address] = feedId.toBn();

        await fsp.writeFile(this.feedsPath, JSON.stringify(feeds, null, 4));
    }
}

export default State;
