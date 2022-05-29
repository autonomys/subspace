// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
// Copyright (C) 2022 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Modified version of SS58 parser extracted from Substrate in order to not pull the whole
//! `sp-core` into farmer application

use base58::FromBase58;
use ss58_registry::Ss58AddressFormat;
use subspace_core_primitives::{PublicKey, PUBLIC_KEY_LENGTH};
use thiserror::Error;

const PREFIX: &[u8] = b"SS58PRE";
const CHECKSUM_LEN: usize = 2;

/// An error type for SS58 decoding.
#[derive(Debug, Error)]
pub(crate) enum Ss58ParsingError {
    /// Base 58 requirement is violated
    #[error("Base 58 requirement is violated")]
    BadBase58,
    /// Length is bad
    #[error("Length is bad")]
    BadLength,
    /// Invalid SS58 prefix byte
    #[error("Invalid SS58 prefix byte")]
    InvalidPrefix,
    /// Disallowed SS58 Address Format for this datatype
    #[error("Disallowed SS58 Address Format for this datatype")]
    FormatNotAllowed,
    /// Invalid checksum
    #[error("Invalid checksum")]
    InvalidChecksum,
}

/// Some if the string is a properly encoded SS58Check address.
pub(crate) fn parse_ss58_reward_address(s: &str) -> Result<PublicKey, Ss58ParsingError> {
    let data = s.from_base58().map_err(|_| Ss58ParsingError::BadBase58)?;
    if data.len() < 2 {
        return Err(Ss58ParsingError::BadLength);
    }
    let (prefix_len, ident) = match data[0] {
        0..=63 => (1, data[0] as u16),
        64..=127 => {
            // weird bit manipulation owing to the combination of LE encoding and missing two
            // bits from the left.
            // d[0] d[1] are: 01aaaaaa bbcccccc
            // they make the LE-encoded 16-bit value: aaaaaabb 00cccccc
            // so the lower byte is formed of aaaaaabb and the higher byte is 00cccccc
            let lower = (data[0] << 2) | (data[1] >> 6);
            let upper = data[1] & 0b00111111;
            (2, (lower as u16) | ((upper as u16) << 8))
        }
        _ => return Err(Ss58ParsingError::InvalidPrefix),
    };
    if data.len() != prefix_len + PUBLIC_KEY_LENGTH + CHECKSUM_LEN {
        return Err(Ss58ParsingError::BadLength);
    }
    let format: Ss58AddressFormat = ident.into();
    if format.is_reserved() {
        return Err(Ss58ParsingError::FormatNotAllowed);
    }

    let hash = ss58hash(&data[0..PUBLIC_KEY_LENGTH + prefix_len]);
    let checksum = &hash.as_bytes()[0..CHECKSUM_LEN];
    if data[PUBLIC_KEY_LENGTH + prefix_len..PUBLIC_KEY_LENGTH + prefix_len + CHECKSUM_LEN]
        != *checksum
    {
        // Invalid checksum.
        return Err(Ss58ParsingError::InvalidChecksum);
    }

    let bytes: [u8; PUBLIC_KEY_LENGTH] = data[prefix_len..][..PUBLIC_KEY_LENGTH]
        .try_into()
        .map_err(|_| Ss58ParsingError::BadLength)?;

    Ok(PublicKey::from(bytes))
}

fn ss58hash(data: &[u8]) -> blake2_rfc::blake2b::Blake2bResult {
    let mut context = blake2_rfc::blake2b::Blake2b::new(64);
    context.update(PREFIX);
    context.update(data);
    context.finalize()
}
