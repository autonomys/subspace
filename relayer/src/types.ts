import { U64 } from "@polkadot/types/primitive";
import { Hash } from "@polkadot/types/interfaces";
import { AddressOrPair } from "@polkadot/api/submittable/types";

export type ChainName = Brand<string, 'chain'>;

export interface TxData {
  feedId: U64;
  block: string;
  metadata: Metadata;
  chain: string;
  signer: AddressOrPair;
}

interface Metadata {
  hash: Hash;
  number: string;
}

export interface ParaHeadAndId {
  paraId: string;
  paraHead: Hash;
}

export interface ParachainConfigType {
  url: string;
  paraId: number;
  // TODO: get chain name from api
  chain: string;
}

export type Brand<K, T> = K & { __brand: T; };
