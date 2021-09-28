
import fetch from "node-fetch";
import { EMPTY, defer, from, Observable, catchError } from 'rxjs';
import { retry, shareReplay } from "rxjs/operators";
import { Hash, SignedBlock } from "@polkadot/types/interfaces";
import { U64 } from "@polkadot/types/primitive";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { Logger } from "pino";

type ParachainConstructorParams = {
    feedId: U64;
    url: string;
    chain: string;
    logger: Logger;
    signer: AddressOrPair;
}

class Parachain {
    private url: string;
    private logger: Logger;
    chain: string;
    feedId: U64;
    signer: AddressOrPair;

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
        };

        this.logger.info(`Fetching ${this.chain} parablock: ${hash}`);

        return defer(() => from(fetch(this.url, options)
            .then(response => response.json())
            .then(({ result }) => {
                if (!result) {
                    throw new Error(`Could not fetch ${this.chain} parablock ${hash} from ${this.url}`);
                }
                return result as SignedBlock;
            })))
            // TODO: currently this works, but need more elegant solution
            .pipe(
                retry(3),
                catchError((error) => {
                    this.logger.error(error)
                    return EMPTY
                }),
                shareReplay()
            )
    }
}

export default Parachain;
