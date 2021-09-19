import { ApiPromise } from "@polkadot/api";
import { Logger } from "pino";
import { Block } from "@polkadot/types/interfaces";
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
            hash: "random hash",
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
} as unknown as ApiPromise;

export const loggerMock = {
  info: jest.fn(),
} as unknown as Logger;

export const fetchParaBlockMock = jest.fn(() => Promise.resolve({} as Block));
