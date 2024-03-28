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

//! Primitives for X509 certificate verification

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod host_functions;
mod runtime_interface;

#[cfg(not(feature = "std"))]
extern crate alloc;

pub use crate::runtime_interface::signature_verification_runtime_interface;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime_interface::pass_by;
use sp_runtime_interface::pass_by::PassBy;

/// Signature verification request.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SignatureVerificationRequest {
    /// Der encoded public key info.
    pub public_key_info: DerVec,
    /// Der encoded signature algorithm.
    pub signature_algorithm: DerVec,
    /// Data that is being signed.
    pub data: Vec<u8>,
    /// Signature.
    pub signature: Vec<u8>,
}

impl PassBy for SignatureVerificationRequest {
    type PassBy = pass_by::Codec<Self>;
}

/// DER encoded bytes
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct DerVec(pub Vec<u8>);

impl AsRef<[u8]> for DerVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for DerVec {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}
