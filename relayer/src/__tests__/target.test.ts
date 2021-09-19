import Target from "../target";
import { apiMock, loggerMock } from "../mocks";
import { Observable, of } from "rxjs";
import { TxData } from "../types";
import { U32 } from "@polkadot/types/primitive";

describe("Target class", () => {
  const params = {
    api: apiMock,
    signer: "random signer address",
    logger: loggerMock,
  };

  const blockSubscriptions: Observable<TxData[]>[] = [
    of([{ chainId: 1 as unknown as U32, block: "stringified block" }]),
  ];

  it("should create an instance", () => {
    const target = new Target(params);

    expect(target).toBeInstanceOf(Target);
    expect(target).toHaveProperty("processSubscriptions");
  });

  it("processSubscriptions should send transactions per block per subscription", (done) => {
    const target = new Target(params);
    const stream = target.processSubscriptions(blockSubscriptions);

    stream.subscribe(() => {
      // TODO: check values
      expect(params.api.tx.feeds.put().signAndSend).toHaveBeenCalled();
      // TODO: check tx hash value
      expect(params.logger.info).toHaveBeenCalled();
      done();
    });
  });
});
