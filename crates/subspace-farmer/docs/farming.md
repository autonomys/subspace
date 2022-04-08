`Farming` structure is the abstraction of the farming process for a single
replica plot.

Farming Instance also stores a channel to stop/pause the background farming
task and a handle to make it possible to wait on it.

At high level it can be subdivided in the following parts.

## Slot info update

In order to farm `Farming` background worker subscribes for `SlotInfo` updates
for receiving challenges from network.

Each `SlotInfo` contains:
- The global challenge for the slot
- Solution range for the global challenge
- Current and next epoch salt

## Updating commitments

We need to update in advance commitments if salts changed (because of epoch
change). We spawn several background workers to recommit tags for pieces from
plot.

## Deriving local challenge

Each farmer has its local challenge, as it is signed by its private key.

## Searching for solution

After that we try to search for some tag within the solution range (from
`SlotInfo`) starting from the local challenge in the `Commitments`.

## Constructing `Solution`

If solution is found (piece tag and piece offset on disk is found), we read
encoded piece and its index from `Plot` and construct `Solution` structure.

## Sending solution

We just send `SolutionResponse` which has `Option<Solution>` there.

If we have solution, we also wait for block signing request from node and sign
block header hash.
