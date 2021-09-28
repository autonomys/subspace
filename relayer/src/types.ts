import { U64 } from "@polkadot/types/primitive";
import { Hash } from "@polkadot/types/interfaces";
import { AddressOrPair } from "@polkadot/api/submittable/types";

export type TxData = {
  feedId: U64;
  block: string;
  metadata: Metadata;
  chain: string;
  signer: AddressOrPair;
};

type Metadata = {
  hash: Hash;
  number: string | number;
};

export type ParaHeadAndId = {
  paraId: string;
  paraHead: Hash;
};

export type ParachainConfigType = {
  url: string,
  paraId: number,
  // TODO: get chain name from api
  chain: string,
  signerSeed: string,
}
