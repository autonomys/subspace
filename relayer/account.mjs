import { Keyring } from "@polkadot/api";

export const getAccount = () => {
    const keyring = new Keyring({ type: "sr25519" });
    // TODO: remove hardcoded value
    return keyring.addFromUri("//Alice", { name: "Alice default" });
}