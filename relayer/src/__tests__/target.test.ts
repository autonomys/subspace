import Target from "../target";
import { apiMock, loggerMock, txHashMock, txDataMock } from "../mocks";
import { of } from "rxjs";

describe("Target class", () => {
  const params = {
    api: apiMock,
    signer: "random signer address",
    logger: loggerMock,
  };

  const blockSubscriptions = [of([txDataMock])];

  it("should create an instance", () => {
    const target = new Target(params);

    expect(target).toBeInstanceOf(Target);
    expect(target).toHaveProperty("processSubscriptions");
  });

  it("processSubscriptions should send transactions per block per subscription", (done) => {
    const target = new Target(params);
    const stream = target.processSubscriptions(blockSubscriptions);

    stream.subscribe(() => {
      expect(params.api.tx.feeds.put).toHaveBeenCalledWith(
        txDataMock.block,
        txDataMock.chainId
      );

      expect(params.api.tx.feeds.put().signAndSend).toHaveBeenCalledWith(
        params.signer,
        { nonce: -1 }
      );

      expect(params.logger.info).toHaveBeenCalledWith(
        `Transaction sent: ${txHashMock}`
      );

      done();
    });
  });

  it.todo(
    "processSubscriptions should return error if transaction submission fails"
  );
});
