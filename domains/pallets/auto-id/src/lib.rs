// Copyright (C) 2023 Subspace Labs, Inc.
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

//! Pallet AutoID

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
use codec::{Decode, Encode};
use frame_support::dispatch::DispatchResult;
use frame_support::traits::Time;
use frame_support::{ensure, PalletError};
pub use pallet::*;
use scale_info::TypeInfo;
use sp_certificate_registry::signature_verification_runtime_interface::verify_signature;
use sp_certificate_registry::{DerVec, SignatureVerificationRequest};
use sp_core::U256;
#[cfg(feature = "std")]
use std::collections::BTreeSet;
use subspace_runtime_primitives::Moment;
use x509_parser::certificate::TbsCertificate;
use x509_parser::prelude::FromDer;

/// Unique AutoId identifier.
pub type Identifier = U256;

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

/// Validity conversion error.
#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum ValidityError {
    Overflow,
    Expired,
}

impl<T: Config> From<ValidityError> for Error<T> {
    fn from(value: ValidityError) -> Self {
        Error::<T>::InvalidValidity(value)
    }
}

impl TryFrom<x509_parser::prelude::Validity> for Validity {
    type Error = ValidityError;

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

/// Root X509 Certificate.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct X509CertificateRoot {
    /// Serial number for this certificate
    pub serial: U256,
    /// Der encoded certificate's subject.
    pub subject: DerVec,
    /// Der encoded certificate's subject's public key info
    pub subject_pki: DerVec,
    /// Validity of the certificate
    pub validity: Validity,
    /// Der encoded full X509 certificate.
    pub raw: DerVec,
    /// A list of all certificate serials issues by the subject.
    /// Serial of root certificate is included as well.
    pub issued_serials: BTreeSet<U256>,
}

/// Leaf X509 certificate issued by a different issuer.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct X509CertificateLeaf {
    /// Issuer identifier of this certificate.
    pub issuer_id: Identifier,
    /// Serial number for this certificate
    pub serial: U256,
    /// Der encoded certificate's subject.
    pub subject: DerVec,
    /// Der encoded certificate's subject's public key info
    pub subject_pki: DerVec,
    /// Validity of the certificate
    pub validity: Validity,
    /// Der encoded full X509 certificate.
    pub raw: DerVec,
}

/// An X509 certificate.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum X509Certificate {
    /// A root X509 certificate.
    Root(X509CertificateRoot),
    /// A leaf certificate issued by a root certificate
    Leaf(X509CertificateLeaf),
}

/// Certificate associated with AutoId.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum Certificate {
    X509(X509Certificate),
}

impl Certificate {
    /// Returns the public key info of a given root certificate.
    fn x509_root_issuer_pki(&self) -> Option<DerVec> {
        match self {
            Certificate::X509(cert) => match cert {
                X509Certificate::Root(cert) => Some(cert.subject_pki.clone()),
                X509Certificate::Leaf(_) => None,
            },
        }
    }

    fn issue_x509_certificate_serial<T: Config>(&mut self, serial: U256) -> DispatchResult {
        match self {
            Certificate::X509(cert) => match cert {
                X509Certificate::Root(cert) => {
                    ensure!(
                        !cert.issued_serials.contains(&serial),
                        Error::<T>::CertificateSerialAlreadyIssued
                    );
                    cert.issued_serials.insert(serial);
                    Ok(())
                }
                // leaf cannot issue certs, return invalid
                X509Certificate::Leaf(_) => Err(Error::<T>::IssuerNotRoot.into()),
            },
        }
    }

    /// Checks if the certificate is valid at this time.
    pub(crate) fn is_valid_at(&self, time: Moment) -> bool {
        match self {
            Certificate::X509(cert) => match cert {
                X509Certificate::Root(cert) => cert.validity.is_valid_at(time),
                X509Certificate::Leaf(cert) => cert.validity.is_valid_at(time),
            },
        }
    }
}

/// A representation of AutoId
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct AutoId {
    /// Unique AutoID identifier.
    pub identifier: Identifier,
    /// Certificate associated with this AutoId.
    pub certificate: Certificate,
}

/// Type holds X509 certificate details used to register an AutoId.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum RegisterAutoIdX509 {
    Root {
        certificate: DerVec,
        signature_algorithm: DerVec,
        signature: Vec<u8>,
    },
    Leaf {
        issuer_id: Identifier,
        certificate: DerVec,
        signature_algorithm: DerVec,
        signature: Vec<u8>,
    },
}

/// Request to register a new AutoId.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum RegisterAutoId {
    X509(RegisterAutoIdX509),
}

#[frame_support::pallet]
mod pallet {
    use crate::{AutoId, Identifier, RegisterAutoId, ValidityError};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::Time;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Time: Time<Moment = subspace_runtime_primitives::Moment>;
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Stores the next auto id identifier.
    #[pallet::storage]
    pub(super) type NextAutoIdIdentifier<T> = StorageValue<_, Identifier, ValueQuery>;

    /// Stores the auto id identifier against an AutoId.
    #[pallet::storage]
    pub(super) type AutoIds<T> = StorageMap<_, Identity, Identifier, AutoId, OptionQuery>;

    #[pallet::error]
    pub enum Error<T> {
        /// Issuer auto id does not exist.
        UnknownIssuer,
        /// Issuer is not a root certificate.
        IssuerNotRoot,
        /// Certificate is invalid,
        InvalidCertificate,
        /// Invalid certificate validity.
        InvalidValidity(ValidityError),
        /// Invalid signature.
        InvalidSignature,
        /// AutoId identifier overflow.
        IdentifierOverflow,
        /// Certificate serial already issued.
        CertificateSerialAlreadyIssued,
        /// Certificate expired.
        ExpiredCertificate,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        NewAutoIdRegistered(Identifier),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Registers a new AutoId after validating the provided certificate.
        #[pallet::call_index(0)]
        // TODO: benchmark
        #[pallet::weight({10_000})]
        pub fn register_auto_id(origin: OriginFor<T>, req: RegisterAutoId) -> DispatchResult {
            ensure_signed(origin)?;
            Self::do_register_auto_id(req)?;
            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    #[allow(dead_code)]
    pub(crate) fn do_register_auto_id(req: RegisterAutoId) -> DispatchResult {
        let current_time = T::Time::now();
        let certificate = match req {
            RegisterAutoId::X509(x509_req) => match x509_req {
                RegisterAutoIdX509::Root {
                    certificate,
                    signature_algorithm,
                    signature,
                } => {
                    let (_, tbs_certificate) = TbsCertificate::from_der(certificate.as_ref())
                        .map_err(|_| Error::<T>::InvalidCertificate)?;

                    let req = SignatureVerificationRequest {
                        public_key_info: tbs_certificate.subject_pki.raw.to_vec().into(),
                        signature_algorithm,
                        data: certificate.0.clone(),
                        signature,
                    };
                    verify_signature(req).ok_or(Error::<T>::InvalidSignature)?;

                    let serial = U256::from_big_endian(&tbs_certificate.serial.to_bytes_be());
                    let validity = Validity::try_from(tbs_certificate.validity)
                        .map_err(Error::<T>::InvalidValidity)?;
                    ensure!(
                        validity.is_valid_at(current_time),
                        Error::<T>::InvalidValidity(ValidityError::Expired)
                    );

                    Certificate::X509(X509Certificate::Root(X509CertificateRoot {
                        serial,
                        subject: tbs_certificate.subject.as_raw().to_vec().into(),
                        subject_pki: tbs_certificate.subject_pki.raw.to_vec().into(),
                        validity,
                        raw: certificate,
                        issued_serials: BTreeSet::from([serial]),
                    }))
                }
                RegisterAutoIdX509::Leaf {
                    issuer_id,
                    certificate,
                    signature_algorithm,
                    signature,
                } => {
                    let mut issuer_auto_id =
                        AutoIds::<T>::get(issuer_id).ok_or(Error::<T>::UnknownIssuer)?;
                    let issuer_pki = issuer_auto_id
                        .certificate
                        .x509_root_issuer_pki()
                        .ok_or(Error::<T>::IssuerNotRoot)?;

                    ensure!(
                        issuer_auto_id.certificate.is_valid_at(current_time),
                        Error::<T>::ExpiredCertificate
                    );

                    let (_, tbs_certificate) = TbsCertificate::from_der(certificate.as_ref())
                        .map_err(|_| Error::<T>::InvalidCertificate)?;

                    let req = SignatureVerificationRequest {
                        public_key_info: issuer_pki,
                        signature_algorithm,
                        data: certificate.0.clone(),
                        signature,
                    };
                    verify_signature(req).ok_or(Error::<T>::InvalidSignature)?;
                    let validity = Validity::try_from(tbs_certificate.validity)
                        .map_err(Error::<T>::InvalidValidity)?;
                    ensure!(
                        validity.is_valid_at(current_time),
                        Error::<T>::InvalidValidity(ValidityError::Expired)
                    );

                    let serial = U256::from_big_endian(&tbs_certificate.serial.to_bytes_be());
                    issuer_auto_id
                        .certificate
                        .issue_x509_certificate_serial::<T>(serial)?;

                    AutoIds::<T>::insert(issuer_id, issuer_auto_id);

                    Certificate::X509(X509Certificate::Leaf(X509CertificateLeaf {
                        issuer_id,
                        serial,
                        subject: tbs_certificate.subject.as_raw().to_vec().into(),
                        subject_pki: tbs_certificate.subject_pki.raw.to_vec().into(),
                        validity,
                        raw: certificate,
                    }))
                }
            },
        };

        let auto_id_identifier = NextAutoIdIdentifier::<T>::get();
        let next_auto_id_identifier = auto_id_identifier
            .checked_add(Identifier::one())
            .ok_or(Error::<T>::IdentifierOverflow)?;
        NextAutoIdIdentifier::<T>::put(next_auto_id_identifier);

        let auto_id = AutoId {
            identifier: auto_id_identifier,
            certificate,
        };

        AutoIds::<T>::insert(auto_id_identifier, auto_id);

        Self::deposit_event(Event::<T>::NewAutoIdRegistered(auto_id_identifier));
        Ok(())
    }
}
