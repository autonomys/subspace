# Design

The farmer typically runs two processes in parallel: plotting and farming.

## Plotting

Think of it as the following pipeline:

1. [Farmer receives new blocks from the blockchain](./src/archiving.rs)
2. [Archives each of them](./src/archiving.rs)
3. [Encodes each archived piece by applying the time-asymmetric SLOTH permutation as `encode(genesis_piece, farmer_public_key_hash, plot_index)`](./src/plotting.rs)
4. [Each encoding is written to the disk](./src/plotting.rs)
3. [A commitment, or tag, to each encoding is created as `hmac(encoding, salt)` and stored within a binary search tree (BST)](./src/plotting.rs).

This process currently takes ~ 36 hours per TiB on a quad-core machine, but for 1 GiB plotting should take between a few seconds and a few minutes.

## [Farming](./src/farming.rs)

1. Connect to a client and subscribe to `slot_notifications` via JSON-RPC.
2. Given a global challenge as `hash(randomness || slot_index)` and `SOLUTION_RANGE`.
3. Derive local challenge as `hash(global_challenge || farmer_public_key_hash)`.
4. Query the BST for the nearest tag to the local challenge.
5. If it within `SOLUTION_RANGE` return a `SOLUTION` else return `None`
6. All the above can and will happen in parallel to plotting process, so it is possible to participate right away
