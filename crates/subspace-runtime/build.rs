// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::env;
use substrate_wasm_builder::WasmBuilder;

fn main() {
    let relative_target_dir = env!("CARGO_MANIFEST_DIR").to_owned() + "/../../target";
    let target_dir = option_env!("CARGO_TARGET_DIR")
        .or(option_env!("WASM_TARGET_DIRECTORY"))
        .unwrap_or(&relative_target_dir);

    subspace_wasm_tools::create_runtime_bundle_inclusion_file(
        target_dir,
        "parachain-template-runtime",
        "EXECUTION_WASM_BUNDLE",
        "execution_wasm_bundle.rs",
    );

    if env::var("WASM_TARGET_DIRECTORY").is_err() {
        env::set_var("WASM_TARGET_DIRECTORY", target_dir);
    }

    WasmBuilder::new()
        .with_current_project()
        .export_heap_base()
        .import_memory()
        .build();
}
