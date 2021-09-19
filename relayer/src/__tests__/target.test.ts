import Target from "../target";
import { apiMock, loggerMock } from "../mocks";

describe("Target class", () => {
  it("should create an instance", () => {
    const params = {
      api: apiMock,
      signer: "random signer address",
      logger: loggerMock,
    };

    const source = new Target(params);

    expect(source).toBeInstanceOf(Target);
  });
});
