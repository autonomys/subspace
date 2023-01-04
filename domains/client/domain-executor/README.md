# Domain Executor

## Overview

```text
                                  +-------------------------+
  Primary Chain Events            |        Executor         |
                                  |                         |
+----------------------+          |   +----------------+    |
|      New Slot        |------------->| BundleProducer |    |
+----------------------+          |   +----------------+    |
                                  |                         |
                                  |                         |
+----------------------+          |   +-----------------+   |
| Primary Block Import |------------->| BundleProcessor |   |
+----------------------+          |   +-----------------+   |
                                  |                         |
                                  |                         |
                                  +-------------------------+
```

Each executor instance, whether for system domain or core domain, consists of these components:

- `BundleProducer`: Produce a bundle on new slot.
  - `BundleElectionSolver`: Attempt to solve the bundle election challenge on each each slot in order to be allowed to author a bundle.
  - `DomainBundleProposer`: Collect the transactions from transaction pool and a range of receipts upon solving the bundle election challenge successfully.
- `BundleProcessor`: On each imported primary block, the bundle processor extracts the domain-specific bundles from the primary block, compiles the bundles to a list of extrinsics, construct a custom `BlockBuilder` with compiled extrinsics, execute and import the domain block. The receipt of processing the domain block is stored locally and then submitted to the primary chain in some bundle later.
- domain worker: Run the components `BundleProducer` and `BundleProcessor` on the arrived events(new_slot, primary_block_import).
- `GossipMessageValidator`: Validate the bundle gossiped from the domain node peers. Currently, this part is inactive and will be re-enabled in the future.

## Modules structure

- `domain_{block_processor,bundle_producer,bundle_proposer,worker}.rs`/`gossip_message_validator`
  - General executor components, sharing the common logics between system domain and core domain.
- `system_{block_processor,bundle_producer,bundle_proposer,worker}.rs`/`system_gossip_message_validator`
  - Executor components specfic to the system domain.
- `core_{block_processor,bundle_producer,bundle_proposer,worker}.rs`/`core_gossip_message_validator`
  - Executor components specfic to the core domain.

## Run a local testnet

Clone the repo and start a local testnet:

```bash
$ git clone https://github.com/subspace/subspace

$ cd subspace

# Run a primary chain, a system domain and a core domain node in one command:
$ cargo run --bin subspace-node -- --dev -- --alice --dev --ws-port 5678 -- --domain-id 1 --alice --dev --ws-port 6789

# Prepare the reward address beforehand and start a farmer in another terminal:
$ cargo run --bin subspace-farmer -- --base-path tmp-farmer farm --plot-size 100M --reward-address [ADDRESS]
```

```
2023-01-05 00:25:33 [PrimaryChain] 🙌 Starting consensus session on top of parent 0xb5c9e775e81475e5153c60849028bb2be5d1afa7070ec2f2e725a21e23a060d7
2023-01-05 00:25:33 [PrimaryChain] 🎁 Prepared block for proposing at 2 (55 ms) [hash: 0xecaac32f763f9308272b6de285650d76195d132ee0d5e681f3a17da65665b008; parent_hash: 0xb5c9…60d7; extrinsics (12): [0x2f28…df6d, 0x9166…cd9b, 0x5e9f…fc1b, 0x4e47…53a7, 0xccca…82ab, 0x48ff…f888, 0x84af…4239, 0xa3ed…896f, 0xb52f…fd39, 0xd86b…f894, 0xf0ab…ee3f, 0x3f18…8b0c]]
2023-01-05 00:25:33 [PrimaryChain] 🔖 Pre-sealed block for proposal at 2. Hash now 0xf679fa11c20b461bd62d89f5bd42b1c73b2b193f6d2df5e5c7364656cb7d9e44, previously 0xecaac32f763f9308272b6de285650d76195d132ee0d5e681f3a17da65665b008.
2023-01-05 00:25:33 [PrimaryChain] ✨ Imported #2 (0xf679…9e44)
2023-01-05 00:25:33 [SecondaryChain] [apply_extrinsic] after: 0x30f0d98f4bde3789cf8fdc5a5f29acb26d50cbd43a5cbead0d2f213f3eded659
2023-01-05 00:25:33 [CoreDomain] Not enough confirmed blocks for domain: DomainId(1). Skipping...
2023-01-05 00:25:33 [CoreDomain] ✨ Imported #2 (0xd265…af31)
2023-01-05 00:25:33 [SecondaryChain] Not enough confirmed blocks for domain: DomainId(0). Skipping...
2023-01-05 00:25:33 [SecondaryChain] ✨ Imported #2 (0x2fca…317d)
2023-01-05 00:25:33 [CoreDomain] 📦 Claimed bundle at slot 1672849533
2023-01-05 00:25:33 [SecondaryChain] 📦 Claimed bundle at slot 1672849533
2023-01-05 00:25:33 [CoreDomain] Submitted bundle
2023-01-05 00:25:33 [SecondaryChain] Submitted bundle
2023-01-05 00:25:34 [SecondaryChain] 📦 Claimed bundle at slot 1672849534
2023-01-05 00:25:34 [CoreDomain] 📦 Claimed bundle at slot 1672849534
2023-01-05 00:25:34 [SecondaryChain] Submitted bundle
2023-01-05 00:25:34 [CoreDomain] Submitted bundle
2023-01-05 00:25:34 [PrimaryChain] 💤 Idle (0 peers), best: #2 (0xf679…9e44), finalized #0 (0xb171…ae48), ⬇ 0 ⬆ 0
2023-01-05 00:25:34 [PrimaryChain] 🚜 Claimed block at slot 1672849534
2023-01-05 00:25:34 [PrimaryChain] 🗳️ Claimed vote at slot 1672849534
2023-01-05 00:25:34 [PrimaryChain] 🙌 Starting consensus session on top of parent 0xf679fa11c20b461bd62d89f5bd42b1c73b2b193f6d2df5e5c7364656cb7d9e44
2023-01-05 00:25:34 [PrimaryChain] 🎁 Prepared block for proposing at 3 (15 ms) [hash: 0x830be738a562bc8f264bf593a4e66fe5caa4d9acf05c299195adaf93c97f3d5d; parent_hash: 0xf679…9e44; extrinsics (6): [0xd705…47ed, 0xb00e…85b3, 0xd084…986b, 0xbbd5…cf82, 0x7d60…1e57, 0x0e19…ba00]]
2023-01-05 00:25:34 [PrimaryChain] 🔖 Pre-sealed block for proposal at 3. Hash now 0x18b93ababe7ad2e2043afcf9f94440bfa851193858c3c425d3e553de5c7df742, previously 0x830be738a562bc8f264bf593a4e66fe5caa4d9acf05c299195adaf93c97f3d5d.
2023-01-05 00:25:34 [PrimaryChain] ✨ Imported #3 (0x18b9…f742)
2023-01-05 00:25:34 [CoreDomain] Not enough confirmed blocks for domain: DomainId(1). Skipping...
2023-01-05 00:25:34 [CoreDomain] ✨ Imported #3 (0x3f5a…9a68)
2023-01-05 00:25:34 [SecondaryChain] [apply_extrinsic] after: 0x904b59ac373a7466b205469d2939a42e212d360635d696348c66511c98d324c3
2023-01-05 00:25:34 [SecondaryChain] [apply_extrinsic] after: 0x2abfbba7763441d8db853fc05b03d88967a00a0a726d068609aca8fb3631bcf9
```
