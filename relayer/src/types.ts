import { U64 } from "@polkadot/types/primitive";
import { Hash } from "@polkadot/types/interfaces";
import Parachain from "./parachain";

export type ChainName = Brand<string, 'chain'>;

export interface TxData {
  feedId: U64;
  block: string;
  metadata: Metadata;
  chain: ChainName;
}

interface Metadata {
  hash: Hash;
  number: string;
}

export interface ParaHeadAndId {
  paraId: string;
  paraHead: Hash;
}

export type ParachainsMap = Map<string, Parachain>;

export type Brand<K, T> = K & { __brand: T; };
