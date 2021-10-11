import * as fs from "fs";
import { BN } from '@polkadot/util';

const lastBlockPath = './state/last_processed_block.json';

export const saveLastProcessedBlock = (chain: string, number: BN) => {
    return fs.promises.readFile(lastBlockPath, 'utf8').then((file) => {
        const lastProcessedBlockRecord = JSON.parse(file);

        lastProcessedBlockRecord[chain] = number;

        return fs.promises.writeFile(lastBlockPath, JSON.stringify(lastProcessedBlockRecord, null, 4));
    });
};

const feedsPath = './state/feeds.json';

export const getFeedIdByAddress = async (address: string) => {
    const file = await fs.promises.readFile(feedsPath, 'utf8');
    const feeds = JSON.parse(file);

    return feeds[address];
};

export const saveFeedId = async (address: string, feedId: BN) => {
    const file = await fs.promises.readFile(feedsPath, 'utf8');
    const feeds = JSON.parse(file);

    feeds[address] = feedId.toBn();

    await fs.promises.writeFile(feedsPath, JSON.stringify(feeds, null, 4));
};
