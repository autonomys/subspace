import { U64, U32 } from "@polkadot/types/primitive";
import { Hash } from "@polkadot/types/interfaces";

export type TxData = {
  block: string;
  metadata: Metadata;
};

type Metadata = {
  feedId: U64;
  hash: Hash;
  number: U32;
};
