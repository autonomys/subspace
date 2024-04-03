# pallet-grandpa-finality-verifier
License: Apache-2.0

GRANDPA finality verifier is used to verify the justifications provided within the substrate based blocks indexing them on our DSN.

The pallet is responsible for:
- providing a basic abstraction over any substrate based chains through `Chain` trait.
- decoding the block and its components.
- verifying the blocks and its justifications using the current authority set the block was produced in.
- importing any authority set changes from the header after the verification.

This pallet is not responsible for:
- verifying or recognizing the forks. So this is left for the admin to reinitialize the chain state after the fork.
