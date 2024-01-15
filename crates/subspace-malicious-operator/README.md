# The intentional malicious operator node

NOTE: ****this is only use for testing purpose****

The malicious operator node act as a regular [domain operator](../../domains/README.md) but it will intentionally and continuously produce malicious content to test if the network can handle it properly.

### How it works

Most parts of the malicious operator act exactly the same as the regular domain operator except its bundle producer. When it produce a bundle, the bundle will be tampered with malicious content with probability before submitting to the consensus chain.

Currently, it supports produce:
- Invalid bundle
- Fraudulent ER

When the operator submit malicious content to the consensus chain, the honest operator in the network will detect and submit fraud proof that target these content, and cause the malicious operator being slashed and baned from submitting bundle.

The malicious operator node will detect the slashing and register a new operator as the malicious operator, moreover, it will enforce the epoch transition to accelerate the onboard of the new malicious operator, and contiune producing malicious content.

### Build from source

```bash
cargo build -r subspace-malicious-operator
```

### Run

The malicious operator node take the same args as the regular domain operator, please refer to [Domain operator](../../domains/README.md).

A few notable differences:
- The malicious operator node will ignore the `--operator-id` arg if specified, instead it will register new operator internally and automatically and using their id to produce malicious content.
- The malicious operator node requires the consensus chain sudo key pair to run in the network.
    - With `--chains dev`, Alice is the sudo account and its key pair is already exist in the node.
    - With `--chain devnet`, the sudo key pair need to insert into the keystore with `subspace-node key insert --suri "<Secret phrase>" --key-type sub_ --scheme sr25519 --keystore-path <PATH>`.
