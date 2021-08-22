# Milestone 3 - Security

The following document outlines security measures against well-known attacks in PoC. The reader is advised to first read [Subspace's design](https://github.com/subspace/substrate/blob/w3f-spartan-ms-3/frame/spartan/design.md) in order to understand these better.

## Lazy Farming (Sybil Attack)

A farmer's chance of winning a leader election only depends on the number of encodings it stores. A farmer with space for *n* encodings has two choices:

1. Honest farming - store one encoding each of *n* different pieces (under one public key)
2. Lazy farming  - store *n* encodings of one piece (under *n* public keys). 

We would like farmers to follow honest farming as it results in better replication of the whole blockchain history. A rational farmer in Subspace may prefer lazy farming because they save on network bandwidth for downloading multiple pieces. Note that in Spartan, a farmer derives their plot from only one *Genesis* piece, so does not gain anything by lazy farming.

Although similar to a Sybil attack, this is not a direct attack on consensus. Subspace's PoC consensus is already Sybil resistant because the chance of winning a leader election only depends on the total number of encodings, not on the number of identities. Lazy farming however impacts Subspace's distributed storage network because the entire blockchain history may not be stored. Lazy farming can also exacerbate a compression attack, which is discussed in the next section.

### Solution

To deter lazy farming, we require farmers to compute one local challenge per public key. Precisely, for each slot, a farmer computes the global `challenge` as `Hash(epoch_randomness||slot)`. The farmer then computes their `local_challenge` as `Hash(challenge||public_key_hash)`.

Suppose that a farmer stores *n* encodings on disk. In the honest farming strategy, the farmer computes one local challenge every slot and queries the binary search tree (BST) to find the closest commitment. This requires log(*n*) lookups since the binary seach tree is sorted. In the lazy farming strategy, the farmer computes *n* local challenges (one for each public key) and must compare each challenge with the commitment for the encoding from the corresponding public key (*n* lookups). When the number of encodings stored by the farmer is large, the lazy farming strategy incurs a huge overhead of BST lookups (memory reads) in every slot which will quickly overcome the one-time cost of downloading and plotting distinct pieces. Thus, a rational farmer would prefer to first store one entire replica of the blockchain history with a single public key before using additional storage to store multiple replicas with different public keys

## Compression Attack

This is an example of a space-time trade-off attack where an attacker may use additional computation to save on storage. 

A Subspace farmer may choose to discard the encodings, and store only the much smaller BST of commitments and one single copy of the unencoded blockchain. Since the leader elections only require the commitments, the farmer can win leader elections without storing the encodings. Once they produce a block, the farmer encodes the piece on-demand to generate the proof. Thus, the farmer only uses a fraction of the required storage while encoding pieces on-demand to win the leader elections. Thus, an attacker can launch a 51% attack even without owning 51% of the network's storage, but by using additional computation. This attack is exacerbated by the lazy farming strategy because the attacker only needs to store one piece, and encode it on-demand with different public keys. Then the attacker's actual storage is very little - only one unencoded piece and the commitments.

### Solution

To deter this attack, the commitments include a salt, which is updated at regular intervals (eons). This makes the compression attack harder because an attacker would have to re-encode their pieces every time the salt changes.

To analyze the cost of the compression attack, let *t_eon* be the salt update interval (a protocol parameter), *P* be the piece size (4 KiB) and let *S* be the storage (in bytes) pledged by a farmer for a time horizon *T*.

Let *C_s* be the cost of storage media (HDD/SSD) in $/byte. Let *C_salt* be the power cost of reading the encoding from disk, re-commiting with the new salt and updating the binary search tree as per the honest protocol (in $/encoding). Let *C_e* be the power cost of encoding a piece, recommiting with the new salt and updating the BST as per the compression attack, in $/encoding. Let *C_cpu* be the cost of a CPU + memory configuration that can encode one piece per *t_enc* seconds.

**Honest strategy:** An honest farmer initially stores *S* bytes worth of encodings to disk. Additionally, they store the binary search tree of commitments to disk. (Note that if the size of a piece/encoding is 4 KiB and the size of a commitment is 8 B, the storage required for the binary search tree is *S* * 8/4096 = *S*/256 bytes, which is much smaller than the *S* bytes required for the encodings themseleves, hence can be ignored.) 

A one-time cost of *C_s* * *S* is paid initially to buy *S* bytes of storage. Everytime the salt is updated (*T/t_eon* times in *T* time), *S/P* encodings must be re-commited. The cost of running the honest strategy can be estimated as 

![Honest strategy cost equation](http://latex.codecogs.com/png.latex?C_%7Bhon%7D%20%3D%20%5Ctext%7Bplotting%20cost%20&plus;%20re-commit%20cost%7D%20%3D%20C_s%5Ccdot%20S%20&plus;%20C_%7Bsalt%7D%5Ccdot%20%28S/P%29%20%5Ccdot%20T/t_%7Beon%7D.)

Note that the initial cost of plotting and the power cost of running the rest of the protocol is not counted because this cost is common among both the strategies.

**Attacker's strategy:** We consider a strategy where the attacker pretends to have *S* bytes of storage, but actually uses very little storage at the cost of computation for on-demand encoding. The attacker stores only one un-encoded copy of one piece, and commitments on encodings computed with different public keys. As discussed above, the storage cost of the commitments is negligible. On the other hand, the attacker must buy computing hardware and re-compute all the encodings every time the salt is updated. One computer costing *C_cpu* can only compute *t_eon/t_enc* encodings in one eon, so the attacker must buy enough CPU cores to be able to encode *S/P* pieces in one eon. Further, there is an operational cost of encoding and re-commiting all these pieces every eon. The attacker's cost is at least

![Compression attack cost equation](http://latex.codecogs.com/png.latex?C_%7Bcomp%7D%20%3D%20%5Ctext%7Bcomputer%20cost%20&plus;%20encoding%20cost%7D%20%3D%20C_%7Bcpu%7D%5Ccdot%20%5Cfrac%7BS/P%7D%7Bt_%7Beon%7D/t_%7Benc%7D%7D%20&plus;%20C_e%5Ccdot%20%28S/P%29%5Ccdot%20T/t_%7Beon%7D.)

**Comparison:** Over a long time horizon *T*, we expect the honest strategy to be the rational choice if its operational cost is lower, i.e. *C_salt < C_e*. This is achieved by using an encoding function that is slow and hard to parallelize (such as repeated squaring in a group). Thus, encoding a piece requires significant amount of computation power (it takes 250 us to encode a single piece in our best benchmark). However, the re-commitment only requires reading an encoding from disk and computing an HMAC - this involves very little computation and the 20 us it takes per commitment is limited by the disk read bandwidth. Thus, the power cost of the re-commitment in the honest strategy is expected to be lower than the power cost of on-demand encoding in the attacker's strategy.

Based on our recent benchmarks, a 12-core AMD 5900x CPU with a 3600 MHz, 16 GB RAM (costing about $850) can encode one piece per 18 us (throughput). If an eon is 1 day, with 18 us per encoding, roughly a 20 TB plot can be encoded in 1 day with just one such computer. Meanwhile, 20 TB of hard disk storage can be purchased for around $500. This quick calculation suggests that the compression attack would require both additional capital cost and additional running costs over the honest strategy, while the received rewards are the same.

## Simulation Attack

The simulation attack (sometimes called *Nothing at Stake*) is an attack vector that is common to all PoS and PoC protocols. In the event of an honest fork, a farmer can extend multiple branches using the same stake or storage. By doing this over and over, an attacker can magnify their effective storage by a factor of *e*, hence an attacker only requires 27% of the storage to do a double-spend attack. [[Chia](https://www.chia.net/assets/ChiaGreenPaper.pdf), [Bagaria et al](https://arxiv.org/abs/1910.02218)., [Dembo et al](https://arxiv.org/abs/1910.02218).]. 

To mitigate this attack, we use the same solution as in [BABE](https://research.web3.foundation/en/latest/polkadot/block-production/Babe.html) and [Ouroboros Praos](https://eprint.iacr.org/2017/573.pdf), which is to reuse the block-producing challenge over several slots. As the slot update interval (epoch) is increased, the security threshold increases from 27% to 50%. at the cost of allowing each farmer to predict ahead of time the slots in which they would be elected as a leader.

![As the slot update interval (epoch) is increased, the security threshold increases from 27% to 50%. At an epoch duration of 32 blocks (3 mins), the security is up to 42%. At an epoch duration of 256 blocks (26 mins), the security is up to 47%)](c-correlation.png)

## Handling Equivocation

In an equivocation attack, a farmer signs two or more different, yet valid, blocks at the same height (i.e. the same timeslot). Since the proofs-of-replication and the block content are effectively decoupled in PoC, a farmer is able to generate many different valid content blocks for the same proof, perhaps by re-ordering the transactions. They could then release the blocks to different sides of the network at the same time and sow confusion while spamming the honest network with many valid blocks, perhaps in conjunction with some other, more serious attack.

### Solution

In proof-of-stake consensus, the problem is dealt with by slashing the stake deposit of any node who equivocates, as this is a provable offense, since both blocks would be signed by the same private key. Since Subspace is a permissionless PoC protocol we have to find another way. Recall from the previous section on Lazy Farming, that Subspace is sybil-resistant through the employment of a local challenge. This incentivizes farmers to store each plot under a single Node ID (public key) effecitvely binding the plot and the public key together. While there is no stake to *slash*, we can still burn the plot, by adding any farmer who provably equivocates to a black-list and then screening all new proofs against this list. This means that any farmer who equivocates may as well discard their plot (and the time and energy required to create it) since it will no longer be able to produce valid solutions.  Note that we may use hash maps or bloom filters to make the screening cost constant and negilgible as the block list grows (else this itself could be an attack vector). 

## Safety and Liveness

Given the following assumptions:

1. Spartan (and Subspace) may be treated as a secure extension of a Nakamoto-style or longest-chain consensus protocol, originating with Bitcoin under PoW, extended to Ouroboros Praos under PoS, as (largely) implemented in BABE and refactored for Spartan PoC.
2. The evaluation of the plot (or, more specifically, the BST) can be modeled as a random oracle, similar to evaluating a hash function in PoW or evaluating a verifiable random function (VRF) in PoS.
3. The countermeasures described above provide security against the sybil, simulation, equivocation, space-time trade-off, compression, and long-range attacks.
4. Strategies that replace storage with computation (space-time trade-offs and compression attacks) are more expensive than the honest strategy, and hence are economically irrational.

Then it follows that no single economically rational adversary with less than 47% of total network storage may attack the safety (i.e., double-spend) or liveness (i.e., censor transactions) of the protocol. This would follow from the safety and liveness proofs for the Bitcoin backbone and Ouroboros Praos. We are currently designing a proof-of-time layer to make the long-range attack infeasible and space-time trade-offs irrational. A specification of this design and a formal justification of these assumptions is work in progess and will be done in the near future.
