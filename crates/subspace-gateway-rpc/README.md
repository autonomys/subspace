## Subspace Gateway RPCs

RPC API for Subspace Gateway.

### Using the gateway RPCs

The gateway RPCs can fetch data using object mappings supplied by a node.

Launch a node using the instructions in its README, and wait for mappings from the node RPCs:
```bash
$ websocat --jsonrpc ws://127.0.0.1:9944
subspace_subscribeObjectMappings
```

```json
{
  "jsonrpc": "2.0",
  "method": "subspace_archived_object_mappings",
  "params": {
    "subscription": "o7M85uu9ir39R5PJ",
    "result": {
      "v0": {
        "objects": [
          ["0000000000000000000000000000000000000000000000000000000000000000", 0, 0]
        ]
      }
    }
  }
}
```

Then use those mappings to get object data from the gateway RPCs:
```bash
$ websocat --jsonrpc ws://127.0.0.1:9955
subspace_fetchObject ["v0": { "objects": [["0000000000000000000000000000000000000000000000000000000000000000", 0, 0]]}]
```

```json
{
  "jsonrpc": "2.0",
  "result": ["00000000"]
}
```
