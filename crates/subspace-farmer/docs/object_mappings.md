`ObjectMappings` is a simple type-safe wrapper around rocksdb.

Apart from retrieving pieces we might want to retrieve and store arbitrary length objects:
- files
- blocks
- ...

For that we also need to know the location of object and its size.

You can consider it as a map from *object hash* to the *object offset* in order to
retrieve it from the plot.
