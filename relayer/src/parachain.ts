
import fetch from "node-fetch";
import { EMPTY, defer, from, Observable, catchError } from 'rxjs';
import { retry, shareReplay } from "rxjs/operators";
import { Hash, SignedBlock } from "@polkadot/types/interfaces";
import { U64 } from "@polkadot/types/primitive";
import { Logger } from "pino";

interface ParachainConstructorParams {
    feedId: U64;
    url: string;
    chain: string;
    logger: Logger;
}

class Parachain {
    private readonly url: string;
    private readonly logger: Logger;
    public chain: string;
    public feedId: U64;

    constructor({ feedId, url, chain, logger }: ParachainConstructorParams) {
        this.feedId = feedId;
        this.url = url;
        this.chain = chain;
        this.logger = logger;
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
                return result;
            })))
            // TODO: currently this works, but need more elegant solution
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
