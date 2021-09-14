import { Keyring } from "@polkadot/api";

export const getAccount = (seed: string) => {
  if (!seed) throw new Error("Seed is not provided");

  const keyring = new Keyring({ type: "sr25519" });

  return keyring.addFromUri(seed);
};
