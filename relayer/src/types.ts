import { U64 } from "@polkadot/types/primitive";
import { Hash } from "@polkadot/types/interfaces";
import Parachain from "./parachain";

export type TxData = {
  feedId: U64;
  block: string;
  metadata: Metadata;
  chain: string;
};

type Metadata = {
  hash: Hash;
  number: string | number;
};

export type ParaHeadAndId = {
  paraId: string;
  paraHead: Hash;
};

export type ParachainsMap = Map<string, Parachain>
