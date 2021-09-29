import { ApiPromise } from "@polkadot/api";
import { Logger } from "pino";
import { of } from "rxjs";
import { Hash } from "@polkadot/types/interfaces";
import { U64 } from "@polkadot/types/primitive";

const stringifiedBlockJson = "stringified block json";

export const txDataMock = {
  feedId: 1 as unknown as U64,
  block: stringifiedBlockJson,
  chain: "Random chain name",
  metadata: {
    hash: "0x84283d2b1b62b7a79d3a4c12464a28dbdcc0c13ca7c046cd82e9826d13c6ce48" as unknown as Hash,
    number: "1,000",
  }
};

const block = {
  block: {
    header: {
      hash: "0x84283d2b1b62b7a79d3a4c12464a28dbdcc0c13ca7c046cd82e9826d13c6ce48" as unknown as Hash,
      number: {
        toString() {
          return "100";
        }
      }
    },
    extrinsics: [],
  },
  toString() {
    return stringifiedBlockJson;
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
                return;
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
                return 10;
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
    return;
  },
} as unknown as ApiPromise;

export const loggerMock = {
  info: jest.fn(),
  error: jest.fn(),
} as unknown as Logger;
