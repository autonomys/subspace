# Relayer

Node.js app which subscribes to the blocks on the source chain and sends block data to the Subspace chain as an extrinsic. Transactions are signed and sent by the Subspace chain account, which is derived from the seed.

Seed as well as source chain and target chain URLs can be specified at `.env`:
```
SOURCE_CHAIN_URL="ws://127.0.0.1:9944"
TARGET_CHAIN_URL="ws://127.0.0.1:9944"
ACCOUNT_SEED="//Alice"
```

## Scripts
`npm start` - run application
`npm test` - run tests

License: Apache-2.0