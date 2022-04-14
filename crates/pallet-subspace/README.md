Subspace consensus pallet.

This pallet is in many ways complementary to `sc-consensus-subspace`.

Pallet maintains crucial state required for Subspace Proof-of-Archival-Storage consensus:
* global randomness
  * based on c-correlation from <https://arxiv.org/abs/1910.02218>
  * is used to later derive together with time slot a global challenge
* solution range, which is a range of valid solution for Proof-of-Archival-Storage puzzle
  * conceptually similar to work difficulty in Proof-of-Work consensus
  * is updated every Era
* salt, which is used for creating plot commitments and is updated every Eon
* inherents for:
  * storing root blocks and maintaining mapping from segment index to corresponding records root such that validity of
    piece from solution can be checked later
  * handling of farmer equivocation (together with `pallet-offences-subspace`) and maintaining list of blocked farmers
    (effectively burned plots)

Pallet also provides handy API for finding block author, block reward address, randomness and some others.

License: Apache-2.0
