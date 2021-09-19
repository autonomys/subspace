import Target from "../target";
import { apiMock, loggerMock } from "../mocks";

describe("Target class", () => {
  it("should create an instance", () => {
    const params = {
      api: apiMock,
      signer: "random signer address",
      logger: loggerMock,
    };

    const target = new Target(params);

    expect(target).toBeInstanceOf(Target);
    expect(target).toHaveProperty("processSubscriptions");
  });
});
