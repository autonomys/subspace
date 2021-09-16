import { Keyring } from "@polkadot/api";
import { KeyringPair } from "@polkadot/keyring/types";

export const getAccount = (seed?: string): KeyringPair => {
  if (!seed) throw new Error("Seed is not provided");

  const keyring = new Keyring({ type: "sr25519" });

  return keyring.addFromUri(seed);
};
