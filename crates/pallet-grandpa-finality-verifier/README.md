# pallet-grandpa-finality-verifier
License: Apache-2.0

GRANDPA finality verifier is used to verify the justifications provided within the substrate based Blocks indexing them on our DSN.

The pallet provides the following functionality
- provides a basic abstraction over any substrate based chains through `Chain` trait.
- decodes the block and its components.
- verifies the blocks and its justifications using the current authority set the block was produced in
- imports any authority set changes from the header after the verification

This pallet does not
- verifies or recognizes the forks. So this is left for the admin to reinitialize the chain state after the fork  
