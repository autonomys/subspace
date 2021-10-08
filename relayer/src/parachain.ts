
import fetch, { RequestInit } from "node-fetch";
import { EMPTY, defer, from, Observable, catchError } from 'rxjs';
import { retry, shareReplay } from "rxjs/operators";
import { Hash, SignedBlock } from "@polkadot/types/interfaces";
import { U64 } from "@polkadot/types/primitive";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { Logger } from "pino";

import { ChainName } from './types';
import { isValidBlock } from './utils';


async function fetchWithTimeout(url: string, options: RequestInit) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), options.timeout);
    const response = await fetch(url, {
        ...options,
        signal: controller.signal
    });
    clearTimeout(id);
    return response;
}

interface ParachainConstructorParams {
    feedId: U64;
    url: string;
    chain: ChainName;
    logger: Logger;
    signer: AddressOrPair;
}

class Parachain {
    private readonly url: string;
    private readonly logger: Logger;
    public readonly chain: ChainName;
    public readonly feedId: U64;
    public readonly signer: AddressOrPair;

    constructor({ feedId, url, chain, logger, signer }: ParachainConstructorParams) {
        this.feedId = feedId;
        this.url = url;
        this.chain = chain;
        this.logger = logger;
        this.signer = signer;
    }

    fetchParaBlock(
        hash: Hash
    ): Observable<SignedBlock> {
        const options = {
            method: "post",
            body: JSON.stringify({
                id: 1,
                jsonrpc: "2.0",
                method: "chain_getBlock",
                params: [hash],
            }),
            headers: { "Content-Type": "application/json" },
            timeout: 8000,
        };

        this.logger.info(`Fetching ${this.chain} parablock: ${hash}`);

        return defer(() => from(fetchWithTimeout(this.url, options)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Could not fetch ${this.chain} parablock ${hash} from ${this.url}: ${response.statusText}`);
                }
                return response.json();
            })
            .then((data) => {
                if (!data.result) {
                    throw new Error(`Could not fetch ${this.chain} parablock ${hash}. Response: ${JSON.stringify(data)}`);
                }

                if (!isValidBlock(data.result)) {
                    throw new Error(`Response result ${JSON.stringify(data.result)} is not a valid block`);
                }

                return data.result;
            })))
            .pipe(
                retry(3),
                catchError((error) => {
                    this.logger.error(error);
                    return EMPTY;
                }),
                shareReplay()
            );
    }
}

export default Parachain;
