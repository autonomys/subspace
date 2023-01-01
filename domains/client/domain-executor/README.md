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

Clone the repo and build the executables:

```bash
git clone https://github.com/subspace/subspace
cd subspace
cargo build --release --bin subspace-farmer --bin subspace-node
```

Start a local testnet:

```bash
# Run a primary chain, a system domain and a core domain node in one command:
subspace-node --dev -d tmp --ws-port 4567 -- --alice --dev --ws-port 5678 -- --domain-id 1 --alice --dev --ws-port 6789

# Prepare the reward address beforehand and start a farmer in another terminal:
subspace-farmer --base-path tmp-farmer farm --plot-size 100M --reward-address [ADDRESS] --node-rpc-url ws://127.0.0.1:4567
```

```
2023-01-01 09:46:37.818  INFO tokio-runtime-worker runtime::domains: [CoreDomain] Submitted bundle
2023-01-01 09:46:37.819  INFO tokio-runtime-worker message::relayer: [SecondaryChain] Not enough confirmed blocks for domain: DomainId(0). Skipping...
2023-01-01 09:46:37.819  INFO tokio-runtime-worker substrate: [SecondaryChain] ✨ Imported #1 (0xb9d4…b722)
2023-01-01 09:46:37.822  INFO tokio-runtime-worker domain_client_executor::system_bundle_producer: [SecondaryChain] 📦 Claimed bundle at slot 1672537597
2023-01-01 09:46:37.824  INFO tokio-runtime-worker runtime::domains: [SecondaryChain] Submitted bundle
2023-01-01 09:46:38.003  INFO tokio-runtime-worker domain_client_executor::system_bundle_producer: [SecondaryChain] 📦 Claimed bundle at slot 1672537598
2023-01-01 09:46:38.006  INFO tokio-runtime-worker runtime::domains: [SecondaryChain] Submitted bundle
2023-01-01 09:46:38.006  INFO tokio-runtime-worker domain_client_executor::core_bundle_producer: [CoreDomain] 📦 Claimed bundle at slot 1672537598
2023-01-01 09:46:38.008  INFO tokio-runtime-worker runtime::domains: [CoreDomain] Submitted bundle
2023-01-01 09:46:38.414  INFO tokio-runtime-worker subspace: [PrimaryChain] 🚜 Claimed block at slot 1672537598
2023-01-01 09:46:38.414  INFO tokio-runtime-worker sc_basic_authorship::basic_authorship: [PrimaryChain] 🙌 Starting consensus session on top of parent 0xce4d69139191607f88de9054b8e26d5017cc68e26a62d0efc62b23a55733bd4f
2023-01-01 09:46:38.415 DEBUG tokio-runtime-worker runtime::system: [PrimaryChain] [2] 0 extrinsics, length: 7230 (normal 0%, op: 0%, mandatory 0%) / normal weight:Weight(ref_time: 395936000, proof_size: 0) (0%) op weight Weight(ref_time: 0, proof_size: 0) (0%) / mandatory weight Weight(ref_time: 824493002, proof_size: 0) (0%)
2023-01-01 09:46:38.416  INFO tokio-runtime-worker sc_basic_authorship::basic_authorship: [PrimaryChain] 🎁 Prepared block for proposing at 2 (0 ms) [hash: 0x4795be3548e0a16144786a9704100d4391f14c499e1e3fd11db799bc44ed5536; parent_hash: 0xce4d…bd4f; extrinsics (5): [0x156f…e6c7, 0xe59c…42d7, 0x7977…2d87, 0xdafa…ae07, 0x8cc4…1343]]
2023-01-01 09:46:38.416  INFO tokio-runtime-worker subspace: [PrimaryChain] 🔖 Pre-sealed block for proposal at 2. Hash now 0x300a2292828e8e05689bd581cc4a50eddfbebd6f4f050fc77a5fd014a791282b, previously 0x4795be3548e0a16144786a9704100d4391f14c499e1e3fd11db799bc44ed5536.
2023-01-01 09:46:38.422  INFO tokio-runtime-worker substrate: [PrimaryChain] ✨ Imported #2 (0x300a…282b)
2023-01-01 09:46:38.425  INFO tokio-runtime-worker domain::runtime::executive: [SecondaryChain] [apply_extrinsic] after: 0xb800a45a4bbee0ec49beb8ecdfd2fdfc47eaa650872089168b4d6fb83a699502
2023-01-01 09:46:38.425 DEBUG tokio-runtime-worker runtime::system: [CoreDomain] [2] 0 extrinsics, length: 0 (normal 0%, op: 0%, mandatory 0%) / normal weight:Weight(ref_time: 0, proof_size: 0) (0%) op weight Weight(ref_time: 0, proof_size: 0) (0%) / mandatory weight Weight(ref_time: 458523001, proof_size: 0) (0%)
2023-01-01 09:46:38.426  INFO tokio-runtime-worker substrate: [CoreDomain] ✨ Imported #2 (0xdcf9…3834)
2023-01-01 09:46:38.426  INFO tokio-runtime-worker message::relayer: [CoreDomain] Not enough confirmed blocks for domain: DomainId(1). Skipping...
2023-01-01 09:46:38.426  INFO tokio-runtime-worker domain::runtime::executive: [SecondaryChain] [apply_extrinsic] after: 0xb5ac1cf110661f9ee0913c13489db0973db4abfc5ba46f56a1691a819139239f
2023-01-01 09:46:38.426 DEBUG tokio-runtime-worker runtime::system: [SecondaryChain] [2] 0 extrinsics, length: 3921 (normal 0%, op: 0%, mandatory 0%) / normal weight:Weight(ref_time: 197968000, proof_size: 0) (0%) op weight Weight(ref_time: 0, proof_size: 0) (0%) / mandatory weight Weight(ref_time: 583523001, proof_size: 0) (0%)
2023-01-01 09:46:38.426  INFO tokio-runtime-worker message::relayer: [SecondaryChain] Not enough confirmed blocks for domain: DomainId(0). Skipping...
2023-01-01 09:46:38.426  INFO tokio-runtime-worker substrate: [SecondaryChain] ✨ Imported #2 (0x8375…c19d)
2023-01-01 09:46:39.002  INFO tokio-runtime-worker domain_client_executor::system_bundle_producer: [SecondaryChain] 📦 Claimed bundle at slot 1672537599
2023-01-01 09:46:39.002  INFO tokio-runtime-worker domain_client_executor::core_bundle_producer: [CoreDomain] 📦 Claimed bundle at slot 1672537599
2023-01-01 09:46:39.005  INFO tokio-runtime-worker runtime::domains: [CoreDomain] Submitted bundle
2023-01-01 09:46:39.005  INFO tokio-runtime-worker runtime::domains: [SecondaryChain] Submitted bundle
2023-01-01 09:46:39.410  INFO tokio-runtime-worker subspace: [PrimaryChain] 🚜 Claimed block at slot 1672537599
```
