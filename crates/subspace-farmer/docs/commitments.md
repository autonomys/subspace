`Commitments` is database for commitments.

You can think of it as mapping from piece tags to plot offsets.

As piece tags are created in `subspace_solving::create_tag` which requires
encoding and salt therefore it needs separate databases for each salt.

Overall it is just wrapper around 2 databases (as we know just 2 salts -
current and the next one). Second one is filled in the background in the
`Plotting` process.

Commitments are updated for each of the inner databases, while search for
solutions (tags and offsets) happens only on the current one.
