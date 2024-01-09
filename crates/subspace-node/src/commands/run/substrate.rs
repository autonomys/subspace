// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

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

//! Copy-paste of Substrate's data structures that are not currently public there.

/// CORS setting
///
/// The type is introduced to overcome `Option<Option<T>>` handling of `clap`.
#[derive(Clone, Debug)]
pub enum Cors {
    /// All hosts allowed.
    All,
    /// Only hosts on the list are allowed.
    List(Vec<String>),
}

impl From<Cors> for Option<Vec<String>> {
    fn from(cors: Cors) -> Self {
        match cors {
            Cors::All => None,
            Cors::List(list) => Some(list),
        }
    }
}

/// Parse cors origins.
pub fn parse_cors(s: &str) -> sc_cli::Result<Cors> {
    let mut is_all = false;
    let mut origins = Vec::new();
    for part in s.split(',') {
        match part {
            "all" | "*" => {
                is_all = true;
                break;
            }
            other => origins.push(other.to_owned()),
        }
    }

    if is_all {
        Ok(Cors::All)
    } else {
        Ok(Cors::List(origins))
    }
}
