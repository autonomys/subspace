import { Keyring } from "@polkadot/api";
import { KeyringPair } from "@polkadot/keyring/types";

export const getAccount = (seed: string): KeyringPair => {
  const keyring = new Keyring({ type: "sr25519" });

  return keyring.addFromUri(seed);
};
