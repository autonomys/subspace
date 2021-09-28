import { ApiPromise } from "@polkadot/api";
import { Logger } from "pino";
import { of } from "rxjs";
import { Block, Hash } from "@polkadot/types/interfaces";
import { U64 } from "@polkadot/types/primitive";

export const txHashMock = "random hash" as unknown as Hash;

export const txDataMock = {
  feedId: 1 as unknown as U64,
  block: "block hex",
  metadata: {
    hash: "random hash" as unknown as Hash,
    number: 1,
  }
};

const block = {
  block: {
    header: {
      hash: "random hash",
      number: {
        toString() {
          return "100"
        }
      }
    },
    extrinsics: [],
  },
  toString() {
    return "block as string";
  },
};

export const apiMock = {
  rx: {
    tx: {
      feeds: {
        put: jest.fn().mockReturnValue({
          signAndSend: jest.fn().mockReturnValue({
            pipe: jest.fn().mockReturnValue({
              subscribe() {
                return
              }
            })
          })
        }),
      },
    },
    rpc: {
      chain: {
        getBlock: jest.fn().mockReturnValue(of(block)),
        subscribeFinalizedHeads() {
          return of({
            hash: "random hash" as unknown as Hash,
            number: {
              toNumber() {
                return 10
              }
            },
          });
        },
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
  createType() {
    return
  },
} as unknown as ApiPromise;

export const loggerMock = {
  info: jest.fn(),
  error: jest.fn(),
} as unknown as Logger;

export const fetchParaBlockMock = jest.fn().mockResolvedValue({} as Block);
