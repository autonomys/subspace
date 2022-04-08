`Plotting` structure is the abstraction on top of the plotting process on the
single replica.

Plotting Instance that stores a channel to stop/pause the background farming
task and a handle to make it possible to wait on this background task.

It does several things.

### Listen for new blocks produced by network

In order to plot whole blockchain history we need to receive network updates,
for that we regularly ask node for its best block number and after that plot
block which is under some confirmation depth constant.

TODO: make plotting account for forks

### Archiving blocks

After that we request finalized (blocks under some confirmation depth from the
best block) blocks. On each of those we call `Archiver::add_block`. It segments
each of them into several segments (each having pieces, objects, and root block).

## Global object mapping

Each segment has `Vec<PieceObjectMapping>`. `PieceObjectMapping` is just a
wrapper around vector of `PieceObject` which is just a structure with object
hash and its offset.

So in order to keep all object mappings we just store those by hash in
`ObjectMappings` db (also just a wrapper around rocksdb).

TODO: Creation of global object mapping should be created once for all replicas
and shared between them.

## Pieces encoding and plot writing

After receiving block archiving each segment has several raw pieces. Each of
those needs to be encoded using time asymmetric permutation
`subspace_solving::SubspaceCodec` (wrapper around `sloth256_189`).

After that pieces are written to the `Plot` by their indexes.

## Updating commitments

Right after writing is done `Plot` returns `WriteResult` which is needed to
update the `Commitments` for the consensus puzzle solving. We will just iterate
over evicted pieces and remove them. After that we just add new pieces written to
the plot.

