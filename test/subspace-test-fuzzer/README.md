## Fuzzing Harness for Subspace

### Fuzzing pallet-domains staking

This harness aims to encompass and encode actions performed by operators in pallet-domains to thoroughly test the
staking implementation in Autonomys.

## Orchestrating the campaign

For optimal results, use a grammar fuzzer such as [autarkie](https://github.com/R9295/autarkie) to consistently generate
valid inputs.

If you cannot use Autarkie, then it is recommended to use [ziggy](https://github.com/srlabs/ziggy/). Ziggy
uses [AFL++](https://github.com/AFLplusplus/AFLplusplus/) and [honggfuzz](https://github.com/google/honggfuzz) under the
hood.
Please refer to its documentation for details.

Command to install ziggy:

```
cargo install --force ziggy cargo-afl honggfuzz grcov
```

Quickstart command to fuzz:

``` bash
 ./scripts/run-fuzzer.sh
```

## MacOS specifics

If the fuzzer exits without any executions, most likely an issue with system settings. To fix these, take a look at
`test/subspace-test-fuzzer/output/subspace-test-fuzzer/logs/afl.log`

The Log file should have clear instructions on what to do to get the fuzzer running.
