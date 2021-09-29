import { ApiPromise } from "@polkadot/api";
import { Logger } from "pino";
import { of } from "rxjs";
import { TypeRegistry } from '@polkadot/types';

const TYPE_REGISTRY = new TypeRegistry();

const stringifiedBlockJson = "stringified block json";

const randomHash = TYPE_REGISTRY.createType("Hash", "0x84283d2b1b62b7a79d3a4c12464a28dbdcc0c13ca7c046cd82e9826d13c6ce48");

export const txDataMock = {
  feedId: TYPE_REGISTRY.createType("U64", 1),
  block: stringifiedBlockJson,
  chain: "Random chain name",
  metadata: {
    hash: randomHash,
    number: "1,000",
  }
};

const block = {
  block: {
    header: {
      hash: randomHash,
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
            hash: randomHash,
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
  debug: jest.fn(),
  warn: jest.fn(),
  trace: jest.fn(),
} as unknown as Logger;
