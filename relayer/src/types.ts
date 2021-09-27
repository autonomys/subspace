import { U64, U32 } from "@polkadot/types/primitive";
import { Hash } from "@polkadot/types/interfaces";

export type TxData = {
  feedId: U64;
  block: string;
  metadata: Metadata;
};

type Metadata = {
  hash: Hash;
  number: U32;
};

export type ParaHeadAndId = {
  paraId: string;
  paraHead: Hash;
};
