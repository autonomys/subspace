## Fuzzing Harness for pallet-domains

This harness aims to encompass and encode actions performed by operators in pallet-domains to thoroughly test the staking implementation in Autonomys.

## Orchestrating the campaign
For optimal results, use a grammar fuzzer such as [autarkie](https://github.com/R9295/autarkie) to consistently generate valid inputs.

If you cannot use Autarkie, then it is recommended to use [ziggy](https://github.com/srlabs/ziggy/). Ziggy uses [AFL++](https://github.com/AFLplusplus/AFLplusplus/) and [honggfuzz](https://github.com/google/honggfuzz) under the hood.
Please refer to its documentation for details.

Command to install ziggy:
```
cargo install --force ziggy cargo-afl honggfuzz grcov
```

Quickstart command to fuzz:
``` bash
cargo ziggy fuzz -j$(nproc) -t1
```

