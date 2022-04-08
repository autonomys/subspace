`Plot` struct is an abstraction on top of plot database. Pieces plotted for single identity,
that's why it is required to supply both address of single replica farmer and maximum amount
of pieces to be stored. It offloads disk writing to separate `PlotWorker` structure, which
plots in the background.

`PlotWorker` converts requests to internal reads/writes to the plot database to bare disk writes.
It prioritizes reads over writes by having separate queues for reads and writes requests, read
requests are executed until exhausted after which at most 1 write request is handled and the
cycle repeats. This allows finding solution with as little delay as possible while introducing
changes to the plot at the same time.

It has also several other databases.

### Piece index hash to offset database

It is represented by `IndexHashToOffsetDB`, which is just typesafe wrapper around rocksdb.
For now instead of piece index hash it stores xor distance beetween piece index hash to identity
(once [321] is fixed it should be no longer the case). It allows `PlotWorker` to both find and
replace pieces by having just piece index.

### Piece offset to piece index database

As piece indexes are sequential and start from zero we just store piece indexes in the raw file.
If we need to find piece index we just index file by piece offset.

[321]: https://github.com/subspace/subspace/issues/321
