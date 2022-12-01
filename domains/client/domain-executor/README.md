# Domain Executor

## Overview

Each executor instance, whether for system domain or core domain, consists of these components:

- `BundleProducer`: Produce a bundle on new slot.
  - `BundleElectionSolver`: Attempt to solve the bundle election challenge on each each slot in order to be allowed to author a bundle.
  - `DomainBundleProposer`: Collect the transactions from transaction pool and a range of receipts upon solving the bundle election challenge successfully.
- `BundleProcessor`: On each imported primary block, the bundle processor extracts the domain-specific bundles from the primary block, compiles the bundles to a list of extrinsics, construct a custom `BlockBuilder` with compiled extrinsics, execute and import the domain block. The receipt of processing the domain block is stored locally and then submitted to the primary chain in some bundle later.
- domain worker: Run the components `BundleProducer` and `BundleProcessor` on the arrived events(new_slot, import_primary_block).
- `GossipMessageValidator`: Validate the bundle gossiped from the domain node peers. Currently, this part is inactive and will be re-enabled in the future.

## Modules structure

- `domain_{block_processor,bundle_producer,bundle_proposer,worker}.rs`/`gossip_message_validator`
  - General executor components, sharing the common logics between system domain and core domain.
- `system_{block_processor,bundle_producer,bundle_proposer,worker}.rs`/`system_gossip_message_validator`
  - Executor components specfic to the system domain.
- `core_{block_processor,bundle_producer,bundle_proposer,worker}.rs`/`core_gossip_message_validator`
  - Executor components specfic to the core domain.
