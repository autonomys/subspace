
import fetch from "node-fetch";
import { Hash, SignedBlock } from "@polkadot/types/interfaces";
import { U64 } from "@polkadot/types/primitive";

class Parachain {
    private url: string;
    feedId: U64;

    constructor({ feedId, url }: { feedId: U64, url: string }) {
        this.feedId = feedId;
        this.url = url;
    }

    async fetchParaBlock(
        hash: Hash
    ): Promise<SignedBlock> {
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

        return (
            fetch(this.url, options)
                .then((response) => response.json())
                .then(({ result }) => {
                    if (!result) {
                        throw new Error(`Could not fetch parablock from ${this.url}`)
                    }
                    return result
                })
                // TODO: clarify how to handle this
                .catch((error) => console.error(error))
        );
    }
}

export default Parachain;
