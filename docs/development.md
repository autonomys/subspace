## Pre-requisites

You'll have to have [Rust toolchain](https://rustup.rs/) installed as well as LLVM, Clang and CMake in addition to usual developer tooling.

Check [crates/subspace-node](../crates/subspace-node/README.md) and [crates/subspace-farmer](../crates/subspace-farmer/README.md) for required dependencies.

## To Farm By Yourself (Offline)

1. Download the executables for your operating system
2. Open your favourite terminal, and go to the folder where you downloaded the executables

**Linux/MacOS:**

1. Make files executable: `chmod +x subspace-farmer-x86_64-*-snapshot subspace-node-x86_64-*-snapshot`
2. Run the node: `./subspace-node-x86_64-*-snapshot --dev --tmp`
3. In macOS, it may prompt that this app is not verified. Click on `cancel` instead of moving it to trash.
   To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
   After this, simply repeat step 4. This time, there will be `Open` button in the prompt, click it to run node.
4. Run the farmer (do this in another terminal): `./subspace-farmer-x86_64-*-snapshot farm`
5. In macOS, it may prompt that this app is not verified. Click on `cancel` instead of moving it to trash.
   To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
   After this, simply repeat step 4. This time, there will be `Open` button in the prompt, click it to run node.

**Windows**

1. Run the node: `subspace-node-x86_64-*-snapshot --dev --tmp`
2. After running this command, Windows may ask you for permissions related to firewall, select `allow` in this case.
3. Run the farmer (do this in another terminal): `subspace-farmer-x86_64-*-snapshot farm`

## To Run From The Source (primarily for developers)

This is a monorepo with multiple binaries and the workflow is typical for Rust projects:

You may need to follow both node & farmer requirements

**node**: https://github.com/autonomys/subspace/tree/main/crates/subspace-node
**farmer**: https://github.com/autonomys/subspace/tree/main/crates/subspace-farmer

- `cargo run --release --bin subspace-node -- run --dev` to run [a node](/crates/subspace-node)
- To [start farming](/crates/subspace-farmer):
  - Single farm: `cargo run --release --bin subspace-farmer -- farm --reward-address REWARD-ADDRESS path=FARM0-DIR,size=FARM0-SIZE`
  - Multiple farms: `cargo run --release --bin subspace-farmer -- farm --reward-address REWARD-ADDRESS path=FARM0-DIR,size=FARM0-SIZE path=FARM1-DIR,size=FARM1-SIZE ...`

NOTE 1: You need to have `nightly` version of Rust toolchain with `wasm32-unknown-unknown` target available or else you'll get a compilation error.
NOTE 2: Following the commands above, you will be farming in an offline setting (by yourself).
NOTE 3: To farm in online setting, you can modify the command accordingly.

You can find readme files in corresponding crates for requirements, multi-node setup and other details.
