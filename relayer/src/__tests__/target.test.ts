import Target from "../target";
import {
    apiMock, loggerMock, txDataMock
} from "../mocks";
// import { ApiPromise } from "@polkadot/api";
import { of } from "rxjs";

describe("Target class", () => {
    const defaultParams = {
        api: apiMock,
        signer: "random signer address",
        logger: loggerMock,
    };

    const blockSubscriptions = of(txDataMock);

    it("should create an instance", () => {
        const target = new Target(defaultParams);

        expect(target).toBeInstanceOf(Target);
        expect(target).toHaveProperty("processSubscriptions");
    });

    it("processSubscriptions should send transactions per block per subscription", (done) => {
        const target = new Target(defaultParams);
        const stream = target.processSubscriptions(blockSubscriptions);

        stream.subscribe(() => {
            expect(defaultParams.api.rx.tx.feeds.put).toHaveBeenCalledWith(
                txDataMock.feedId,
                txDataMock.block,
                JSON.stringify(txDataMock.metadata)
            );

            expect(defaultParams.api.rx.tx.feeds.put().signAndSend).toHaveBeenCalledWith(
                defaultParams.signer,
                { nonce: -1 },
                Promise.resolve
            );

            // TODO: check transaction logging

            done();
        });
    });
});
