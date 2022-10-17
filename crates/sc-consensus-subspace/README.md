# Subspace Proof-of-Archival-Storage consensus

Subspace is a slot-based block production mechanism which uses a Proof-of-Archival-Storage to randomly perform the slot
allocation. On every slot, all the farmers evaluate their disk-based plot. If they have a tag (reflecting a commitment
to a valid encoding) that it is lower than a given threshold (which is proportional to the total space pledged by the
network) they may produce a new block.

Core inputs to the Proof-of-Archival-Storage, such as global randomness and solution range come from the runtime,
see `pallet-subspace` for details.

The fork choice rule is weight-based, where weight is derived from the distance between solution proposed in a block and
the local challenge for particular farmer. The heaviest chain (represents a chain with more storage pledged to it)
will be preferred over alternatives or longest chain is in case of a tie.

For a more in-depth analysis of Subspace consensus can be found in our
[consensus whitepaper](https://subspace.network/news/subspace-network-whitepaper).

This crate contains following major components:
* worker (`sc-consensus-slots`) for claiming slots (block production)
* block verifier that stateless verification of signature and Proof-of-Space
* block import that verifies Proof-of-Archival-Storage and triggers archiving of the history
* archiver worker triggered by block import that ensures history is archived and root blocks are produced at precisely 
  the right time before finishing block import

License: GPL-3.0-or-later WITH Classpath-exception-2.0
