// Copyright (C) 2023 Subspace Labs, Inc.
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

pub(crate) mod cli;
pub(crate) mod evm_chain_spec;

use evm_domain_runtime::AccountId as AccountId20;
use sp_core::crypto::AccountId32;
use sp_core::{ByteArray, H160};
use sp_runtime::traits::Convert;

pub struct AccountId32ToAccountId20Converter;

impl Convert<AccountId32, AccountId20> for AccountId32ToAccountId20Converter {
    fn convert(acc: AccountId32) -> AccountId20 {
        // Using the full hex key, truncating to the first 20 bytes (the first 40 hex chars)
        H160::from_slice(&acc.as_slice()[0..20]).into()
    }
}
