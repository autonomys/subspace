import { ApiPromise } from "@polkadot/api";
import { Logger } from "pino";
import { Block, Hash } from "@polkadot/types/interfaces";
import { of } from "rxjs";

const block = {
  block: {
    header: {
      hash: "random hash",
    },
    extrinsics: [],
  },
};

export const apiMock = {
  rx: {
    rpc: {
      chain: {
        subscribeFinalizedHeads() {
          return of({
            hash: "random hash" as unknown as Hash,
          });
        },
      },
    },
  },
  rpc: {
    chain: {
      getBlock() {
        return block;
      },
    },
  },
  query: {
    system: {
      events: {
        at() {
          return [];
        },
      },
    },
  },
  tx: {
    feeds: {
      put: () => ({
        signAndSend: jest.fn(() =>
          Promise.resolve("random hash" as unknown as Hash)
        ),
      }),
    },
  },
} as unknown as ApiPromise;

export const loggerMock = {
  info: jest.fn(),
} as unknown as Logger;

export const fetchParaBlockMock = jest.fn(() => Promise.resolve({} as Block));
