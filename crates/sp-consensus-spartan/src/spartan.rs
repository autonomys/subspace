// Copyright (C) 2021 Subspace Labs, Inc.
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

//! Spartan-based PoR.

use ring::hmac;
use std::convert::TryInto;
use subspace_core_primitives::Piece;

pub const SIGNING_CONTEXT: &[u8] = b"FARMER";

pub type Tag = [u8; 8];
pub type Salt = [u8; 8];

pub fn is_commitment_valid(encoding: &Piece, tag: &Tag, salt: &Salt) -> bool {
    let correct_tag = create_tag(encoding, salt);
    &correct_tag == tag
}

fn create_tag(encoding: &[u8], salt: &[u8]) -> Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    hmac::sign(&key, encoding).as_ref()[0..8]
        .try_into()
        .unwrap()
}
