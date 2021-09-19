import { U32 } from "@polkadot/types/primitive";
import Source from "../source";
import { apiMock, loggerMock, fetchParaBlockMock } from "../mocks";

describe("Source class", () => {
  it("should create instance", () => {
    const params = {
      api: apiMock,
      chain: "Random relay chain name",
      chainId: 66 as unknown as U32,
      parachains: {
        [45]: "random parachain endpoint url",
      },
      logger: loggerMock,
      fetchParaBlock: fetchParaBlockMock,
    };

    const source = new Source(params);

    expect(source).toBeInstanceOf(Source);
  });
});
