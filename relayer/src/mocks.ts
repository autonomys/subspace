import { ApiPromise } from "@polkadot/api";
import { Logger } from "pino";
import { of } from "rxjs";
import { Block, Hash, SignedBlock } from "@polkadot/types/interfaces";
import { U64, U32 } from "@polkadot/types/primitive";

export const txHashMock = "random hash" as unknown as Hash;

export const txDataMock = {
  feedId: 1 as unknown as U64,
  block: "block hex",
  metadata: {
    hash: "random hash" as unknown as Hash,
    number: 1 as unknown as U32,
  }
};

const block = {
  block: {
    header: {
      hash: "random hash",
    },
    extrinsics: [],
  },
  toHex() {
    return "block hex";
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
  rpc: {
    chain: {
      getBlock: jest.fn().mockResolvedValue(block as unknown as SignedBlock),
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
