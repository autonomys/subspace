## Subspace Gateway RPCs

RPC API for Subspace Gateway.

### Using the gateway RPCs

The gateway RPCs can fetch data using object mappings supplied by a node.

Launch a node with `--create-object-mappings`, and wait for mappings from the node RPCs:
(See the node README for more details.)
```bash
$ subspace-node --create-object-mappings ...
$ websocat --jsonrpc ws://127.0.0.1:9944
subspace_subscribeObjectMappings
```

```json
{
  "jsonrpc": "2.0",
  "method": "subspace_object_mappings",
  "params": {
    "subscription": "o7M85uu9ir39R5PJ",
    "result": {
      "blockNumber": 0,
      "v0": {
        "objects": [
          [
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            0
          ]
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
