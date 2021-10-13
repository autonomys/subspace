// Small utility that can download blocks from Substrate-based chain starting from genesis and store them by block
// number in a directory

import {ApiPromise, WsProvider} from "@polkadot/api";
import {firstValueFrom} from "rxjs";
import * as fs from "fs/promises";

const REPORT_PROGRESS_INTERVAL = process.env.REPORT_PROGRESS_INTERVAL ? parseInt(process.env.REPORT_PROGRESS_INTERVAL) : 100;
const BLOCK_NUMBER_CHUNK_REGEX = /.{1,2}/g;

(async () => {
  const source_chain_rpc = process.env.SOURCE_CHAIN_RPC;
  if (!source_chain_rpc) {
    console.error("SOURCE_CHAIN_RPC environment variable must be set with WS RPC URL");
    process.exit(1);
  }

  const target_dir = process.env.TARGET_DIR;
  if (!source_chain_rpc) {
    console.error("TARGET_DIR environment variable must be set with directory where downloaded blocks must be stored");
    process.exit(1);
  }

  console.info(`Connecting to RPC at ${source_chain_rpc}...`);
  const provider = new WsProvider(source_chain_rpc);
  const api = await ApiPromise.create({
    provider,
  });

  console.log("Retrieving last finalized block...");

  let lastFinalizedBlockNumber = await (async () => {
    const finalizedBlockHash = await firstValueFrom(api.rx.rpc.chain.getFinalizedHead());
    const finalizedHeader = await firstValueFrom(api.rx.rpc.chain.getHeader(finalizedBlockHash));
    return finalizedHeader.number.toNumber();
  })();

  // Keep last finalized block up to date in the background
  api.rx.rpc.chain.subscribeFinalizedHeads().forEach((finalizedHead) => {
    lastFinalizedBlockNumber = finalizedHead.number.toNumber();
  });

  console.info(`Last finalized block is ${lastFinalizedBlockNumber}`);

  console.log(`Downloading blocks into ${target_dir}`);

  const lastDownloadedBlock = await (async () => {
    try {
      return parseInt(await fs.readFile(`${target_dir}/last-downloaded-block`, {encoding: 'utf-8'}));
    } catch {
      return -1;
    }
  })();

  if (lastDownloadedBlock > -1) {
    console.info(`Continuing downloading from block ${lastDownloadedBlock + 1}`);
  }

  let lastDownloadingReportAt;

  for (let blockNumber = lastDownloadedBlock + 1; blockNumber <= lastFinalizedBlockNumber; ++blockNumber) {
    const blockHash = await firstValueFrom(api.rx.rpc.chain.getBlockHash(blockNumber));
    const blockBytes = (await firstValueFrom(api.rx.rpc.chain.getBlock(blockHash))).toU8a();

    // We know it is a number and always matches, hence suppression
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const blockDir = blockNumber.toString().match(BLOCK_NUMBER_CHUNK_REGEX)!.join('/');

    await fs.mkdir(`${target_dir}/${blockDir}`, {recursive: true});
    await fs.writeFile(`${target_dir}/${blockDir}/block-${blockNumber}`, blockBytes)

    if (blockNumber % REPORT_PROGRESS_INTERVAL === 0) {
      const now = Date.now();
      const downloadRate = lastDownloadingReportAt
        ? ` (${(REPORT_PROGRESS_INTERVAL / ((now - lastDownloadingReportAt) / 1000)).toFixed(2)} blocks/s)`
        : "";
      lastDownloadingReportAt = now;

      console.info(
        `Downloaded block ${blockNumber}/${lastFinalizedBlockNumber}${downloadRate}`
      );

      await fs.writeFile(`${target_dir}/last-downloaded-block`, blockNumber.toString());
    }
  }

  console.info("Archived everything");

  process.exit(0);
})();
