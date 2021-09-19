import { ApiPromise } from "@polkadot/api";
import { Logger } from "pino";
import { Block } from "@polkadot/types/interfaces";

export const apiMock = {
  rx: {
    rpc: {
      chain: {
        subscribeFinalizedHeads: jest.fn(),
      },
    },
  },
} as unknown as ApiPromise;

export const loggerMock = {
  info: jest.fn(),
} as unknown as Logger;

export const fetchParaBlockMock = jest.fn(() => Promise.resolve({} as Block));
