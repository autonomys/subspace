This runtime is used for benchmarking the `register_domain_runtime` and `upgrade_domain_runtime` extrinsic.

**Don't use them in production environments!**

To update:
1. Build the `subspace-node` binary
2. Run `subspace-node domain build-genesis-storage --chain dev > evm-domain-genesis-storage`
