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

pub use crate::runtime_interface::auto_id_runtime_interface;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::U256;
use sp_runtime_interface::pass_by;
use sp_runtime_interface::pass_by::PassBy;
use subspace_runtime_primitives::Moment;

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

/// Validity of a given certificate.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct Validity {
    /// Not valid before the time since UNIX_EPOCH
    pub not_before: Moment,
    /// Not valid after the time since UNIX_EPOCH
    pub not_after: Moment,
}

impl Validity {
    /// Checks if the certificate is valid at this time.
    pub fn is_valid_at(&self, time: Moment) -> bool {
        time >= self.not_before && time <= self.not_after
    }
}

/// Generic error type for conversion errors.
#[cfg(feature = "std")]
#[derive(TypeInfo, Encode, Decode, Debug, PartialEq)]
pub enum HostFunctionsConversionError {
    /// Overflow during conversion to `Validity`.
    Overflow,
    /// Failed to fetch common name from subject distinguished name.
    ///
    /// Note that there are multiple reasons for failure or incorrect behavior,
    /// for ex. if the attribute is present multiple times, or is not a UTF-8 encoded string.
    CommonNameNotFound,
}

#[cfg(feature = "std")]
impl TryFrom<x509_parser::prelude::Validity> for Validity {
    type Error = HostFunctionsConversionError;

    fn try_from(value: x509_parser::certificate::Validity) -> Result<Self, Self::Error> {
        Ok(Validity {
            not_before: (value.not_before.timestamp() as u64)
                .checked_mul(1000)
                .and_then(|secs| {
                    secs.checked_add(value.not_before.to_datetime().millisecond() as u64)
                })
                .ok_or(Self::Error::Overflow)?,
            not_after: (value.not_after.timestamp() as u64)
                .checked_mul(1000)
                .and_then(|secs| {
                    secs.checked_add(value.not_after.to_datetime().millisecond() as u64)
                })
                .ok_or(Self::Error::Overflow)?,
        })
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SubjectDistinguishedName {
    /// Common name encoded as a DER vector.
    pub common_name: DerVec,
    /// Raw value of this subject distinguished name.
    pub raw: DerVec,
}

#[cfg(feature = "std")]
impl<'a> TryFrom<x509_parser::prelude::X509Name<'a>> for SubjectDistinguishedName {
    type Error = HostFunctionsConversionError;

    fn try_from(value: x509_parser::prelude::X509Name<'a>) -> Result<Self, Self::Error> {
        use x509_parser::der_parser::asn1_rs::ToDer;

        let common_name = value
            .iter_common_name()
            .next()
            .and_then(|cn| cn.attr_value().to_der_vec().ok())
            .ok_or(HostFunctionsConversionError::CommonNameNotFound)?;

        Ok(SubjectDistinguishedName {
            common_name: common_name.into(),
            raw: value.as_raw().to_vec().into(),
        })
    }
}

/// Decoded Tbs certificate.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct TbsCertificate {
    /// Certificate serial number.
    pub serial: U256,
    /// Certificate subject.
    pub subject: SubjectDistinguishedName,
    /// Certificate subject public key info.
    pub subject_public_key_info: DerVec,
    /// Certificate validity.
    pub validity: Validity,
}

/// DER encoded bytes
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct DerVec(pub Vec<u8>);

impl PassBy for DerVec {
    type PassBy = pass_by::Codec<Self>;
}

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
