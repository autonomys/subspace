import { U64 } from "@polkadot/types/primitive";
import { Hash } from "@polkadot/types/interfaces";
import { AddressOrPair } from "@polkadot/api/submittable/types";
import { BN } from '@polkadot/util';

import Parachain from "./parachain";

export type ChainName = Brand<string, 'chain'>;

export interface TxData {
  feedId: U64;
  block: string;
  metadata: Metadata;
  chain: ChainName;
  signer: AddressOrPair;
}

interface Metadata {
  hash: Hash;
  number: BN;
}

export interface ParaHeadAndId {
  paraId: string;
  paraHead: Hash;
}

export type ParachainsMap = Map<string, Parachain>;

export type Brand<K, T> = K & { __brand: T; };

export interface ParachainConfigType {
  url: string;
  paraId: number;
  // TODO: get chain name from api
  chain: ChainName;
}
