import { U32 } from "@polkadot/types/primitive";
import { Observable } from "rxjs";
import Source from "../source";
import { apiMock, loggerMock, fetchParaBlockMock } from "../mocks";

describe("Source class", () => {
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

  it("should create an instance", () => {
    const source = new Source(params);

    expect(source).toBeInstanceOf(Source);
    expect(source).toHaveProperty("subscribeBlocks");
  });

  it("subscribeBlocks should return an Observable with an array of a single relay chain block", (done) => {
    const source = new Source(params);
    const stream = source.subscribeBlocks();

    expect(stream).toBeInstanceOf(Observable);

    stream.subscribe((data) => {
      expect(data).toHaveLength(1);
      expect(data[0]).toHaveProperty("chainId");
      expect(data[0].chainId).toBe(params.chainId);
      // TODO: add check block value
      done();
    });
  });

  it.todo(
    "subscribeBlocks should return an Observable with an array of multiple blocks (relay chain block and parablocks)"
  );
});
