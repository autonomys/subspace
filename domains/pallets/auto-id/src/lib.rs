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
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode};
use frame_support::dispatch::DispatchResult;
use frame_support::ensure;
use frame_support::traits::Time;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_auto_id::auto_id_runtime_interface::{decode_tbs_certificate, verify_signature};
use sp_auto_id::{DerVec, SignatureVerificationRequest, Validity};
use sp_core::{blake2_256, H256, U256};
#[cfg(feature = "std")]
use std::collections::BTreeSet;
use subspace_runtime_primitives::Moment;

/// Unique AutoId identifier.
pub type Identifier = H256;

/// Serial issued by the subject.
pub type Serial = U256;

/// X509 certificate.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct X509Certificate {
    /// Issuer identifier of this certificate.
    pub issuer_id: Option<Identifier>,
    /// Serial number for this certificate
    pub serial: U256,
    /// Subject common name of the certificate.
    pub subject_common_name: Vec<u8>,
    /// Der encoded certificate's subject's public key info.
    pub subject_public_key_info: DerVec,
    /// Validity of the certificate
    pub validity: Validity,
    /// Der encoded full X509 certificate.
    pub raw: DerVec,
    /// A list of all certificate serials issues by the subject.
    /// Serial of root certificate is included as well.
    pub issued_serials: BTreeSet<Serial>,
    /// Certificate action nonce.
    pub nonce: U256,
}

/// Certificate associated with AutoId.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum Certificate {
    X509(X509Certificate),
}

impl Certificate {
    /// Returns the subject distinguished name.
    #[cfg(test)]
    fn subject_common_name(&self) -> Vec<u8> {
        match self {
            Certificate::X509(cert) => cert.subject_common_name.clone(),
        }
    }

    /// Returns the subject public key info.
    fn subject_public_key_info(&self) -> DerVec {
        match self {
            Certificate::X509(cert) => cert.subject_public_key_info.clone(),
        }
    }

    fn issue_certificate_serial<T: Config>(&mut self, serial: U256) -> DispatchResult {
        match self {
            Certificate::X509(cert) => {
                ensure!(
                    !cert.issued_serials.contains(&serial),
                    Error::<T>::CertificateSerialAlreadyIssued
                );
                cert.issued_serials.insert(serial);
                Ok(())
            }
        }
    }

    fn issuer_id(&self) -> Option<Identifier> {
        match self {
            Certificate::X509(cert) => cert.issuer_id,
        }
    }

    fn serial(&self) -> Serial {
        match self {
            Certificate::X509(cert) => cert.serial,
        }
    }

    /// Checks if the certificate is valid at this time.
    pub(crate) fn is_valid_at(&self, time: Moment) -> bool {
        match self {
            Certificate::X509(cert) => cert.validity.is_valid_at(time),
        }
    }

    /// Deterministically derives an identifier from the certificate.
    ///
    /// The identifier is derived by hashing the subject common name of the certificate.
    /// If the certificate is a leaf certificate, the issuer identifier is combined with the subject common name.
    fn derive_identifier(&self) -> Identifier {
        match &self {
            Certificate::X509(cert) => {
                if let Some(issuer_id) = cert.issuer_id {
                    let mut data = issuer_id.to_fixed_bytes().to_vec();

                    data.extend_from_slice(cert.subject_common_name.as_ref());

                    blake2_256(&data).into()
                } else {
                    // Root certificate
                    blake2_256(cert.subject_common_name.as_ref()).into()
                }
            }
        }
    }

    fn nonce(&self) -> U256 {
        match self {
            Certificate::X509(cert) => cert.nonce,
        }
    }

    fn inc_nonce<T: Config>(&mut self) -> DispatchResult {
        match self {
            Certificate::X509(cert) => {
                cert.nonce = cert
                    .nonce
                    .checked_add(U256::one())
                    .ok_or(Error::<T>::NonceOverflow)?;
                Ok(())
            }
        }
    }
}

/// A representation of AutoId
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct AutoId {
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

/// Signature holds algorithm used and the signature value.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct Signature {
    pub signature_algorithm: DerVec,
    pub value: Vec<u8>,
}

/// Request to register a new AutoId.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum RegisterAutoId {
    X509(RegisterAutoIdX509),
}

/// Specific action type taken by the subject of the Certificate.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum CertificateActionType {
    RevokeCertificate,
    DeactivateAutoId,
}

/// Signing data used to verify the certificate action.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct CertificateAction {
    /// On which AutoId the action is taken.
    pub id: Identifier,
    /// Current nonce of the certificate.
    pub nonce: U256,
    /// Type of action taken.
    pub action_type: CertificateActionType,
}

#[frame_support::pallet]
mod pallet {
    use super::*;
    use crate::{AutoId, Identifier, RegisterAutoId, Serial, Signature};
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

    /// Stores the auto id identifier against an AutoId.
    #[pallet::storage]
    pub(super) type AutoIds<T> = StorageMap<_, Identity, Identifier, AutoId, OptionQuery>;

    /// Stores list of revoked certificates.
    ///
    /// It maps the issuer's identifier to the list of revoked serial numbers of certificates. Before accepting
    /// the certificate, external entities should check if the certificate or its issuer has been revoked.
    #[pallet::storage]
    pub(super) type CertificateRevocationList<T> =
        StorageMap<_, Identity, Identifier, BTreeSet<Serial>, OptionQuery>;

    #[pallet::error]
    pub enum Error<T> {
        /// Issuer auto id does not exist.
        UnknownIssuer,
        /// Unknown AutoId identifier.
        UnknownAutoId,
        /// Certificate is invalid,
        InvalidCertificate,
        /// Invalid signature.
        InvalidSignature,
        /// Certificate serial already issued.
        CertificateSerialAlreadyIssued,
        /// Certificate expired.
        ExpiredCertificate,
        /// Certificate revoked.
        CertificateRevoked,
        /// Certificate already revoked.
        CertificateAlreadyRevoked,
        /// Nonce overflow.
        NonceOverflow,
        /// Identifier already exists.
        AutoIdIdentifierAlreadyExists,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emits when a new AutoId is registered.
        NewAutoIdRegistered(Identifier),
        /// Emits when a Certificate associated with AutoId is revoked.
        CertificateRevoked(Identifier),
        /// Emits when an AutoId is deactivated.
        AutoIdDeactivated(Identifier),
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

        /// Revokes a certificate associated with given AutoId.
        ///
        /// The signature is verified against the issuer's public key.
        // TODO: benchmark
        #[pallet::call_index(1)]
        #[pallet::weight({10_000})]
        pub fn revoke_certificate(
            origin: OriginFor<T>,
            auto_id_identifier: Identifier,
            signature: Signature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::do_revoke_certificate(auto_id_identifier, signature)?;
            Ok(())
        }

        /// Deactivates a given AutoId.
        #[pallet::call_index(2)]
        // TODO: benchmark
        #[pallet::weight({10_000})]
        pub fn deactivate_auto_id(
            origin: OriginFor<T>,
            auto_id_identifier: Identifier,
            signature: Signature,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::do_deactivate_auto_id(auto_id_identifier, signature)?;
            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    pub(crate) fn do_register_auto_id(req: RegisterAutoId) -> DispatchResult {
        let current_time = T::Time::now();
        let certificate = match req {
            RegisterAutoId::X509(x509_req) => match x509_req {
                RegisterAutoIdX509::Root {
                    certificate,
                    signature_algorithm,
                    signature,
                } => {
                    let tbs_certificate = decode_tbs_certificate(certificate.clone())
                        .ok_or(Error::<T>::InvalidCertificate)?;
                    let req = SignatureVerificationRequest {
                        public_key_info: tbs_certificate.subject_public_key_info.clone(),
                        signature_algorithm,
                        data: certificate.0.clone(),
                        signature,
                    };
                    verify_signature(req).ok_or(Error::<T>::InvalidSignature)?;

                    ensure!(
                        tbs_certificate.validity.is_valid_at(current_time),
                        Error::<T>::ExpiredCertificate
                    );

                    Certificate::X509(X509Certificate {
                        issuer_id: None,
                        serial: tbs_certificate.serial,
                        subject_common_name: tbs_certificate.subject_common_name,
                        subject_public_key_info: tbs_certificate.subject_public_key_info,
                        validity: tbs_certificate.validity,
                        raw: certificate,
                        issued_serials: BTreeSet::from([tbs_certificate.serial]),
                        nonce: U256::zero(),
                    })
                }
                RegisterAutoIdX509::Leaf {
                    issuer_id,
                    certificate,
                    signature_algorithm,
                    signature,
                } => {
                    let mut issuer_auto_id =
                        AutoIds::<T>::get(issuer_id).ok_or(Error::<T>::UnknownIssuer)?;
                    let issuer_public_key_info =
                        issuer_auto_id.certificate.subject_public_key_info();

                    ensure!(
                        issuer_auto_id.certificate.is_valid_at(current_time),
                        Error::<T>::ExpiredCertificate
                    );

                    let tbs_certificate = decode_tbs_certificate(certificate.clone())
                        .ok_or(Error::<T>::InvalidCertificate)?;

                    let req = SignatureVerificationRequest {
                        public_key_info: issuer_public_key_info,
                        signature_algorithm,
                        data: certificate.0.clone(),
                        signature,
                    };
                    verify_signature(req).ok_or(Error::<T>::InvalidSignature)?;
                    ensure!(
                        tbs_certificate.validity.is_valid_at(current_time),
                        Error::<T>::ExpiredCertificate
                    );

                    ensure!(
                        !CertificateRevocationList::<T>::get(issuer_id).map_or(false, |serials| {
                            serials.iter().any(|s| {
                                *s == issuer_auto_id.certificate.serial()
                                    || *s == tbs_certificate.serial
                            })
                        }),
                        Error::<T>::CertificateRevoked
                    );

                    issuer_auto_id
                        .certificate
                        .issue_certificate_serial::<T>(tbs_certificate.serial)?;

                    AutoIds::<T>::insert(issuer_id, issuer_auto_id);

                    Certificate::X509(X509Certificate {
                        issuer_id: Some(issuer_id),
                        serial: tbs_certificate.serial,
                        subject_common_name: tbs_certificate.subject_common_name,
                        subject_public_key_info: tbs_certificate.subject_public_key_info,
                        validity: tbs_certificate.validity,
                        raw: certificate,
                        issued_serials: BTreeSet::from([tbs_certificate.serial]),
                        nonce: U256::zero(),
                    })
                }
            },
        };

        let auto_id_identifier = certificate.derive_identifier();
        let auto_id = AutoId { certificate };

        ensure!(
            !AutoIds::<T>::contains_key(auto_id_identifier),
            Error::<T>::AutoIdIdentifierAlreadyExists
        );

        AutoIds::<T>::insert(auto_id_identifier, auto_id);

        Self::deposit_event(Event::<T>::NewAutoIdRegistered(auto_id_identifier));
        Ok(())
    }

    fn do_verify_signature(
        auto_id: &AutoId,
        signing_data: CertificateAction,
        signature: Signature,
    ) -> DispatchResult {
        let Signature {
            signature_algorithm,
            value: signature,
        } = signature;
        let req = SignatureVerificationRequest {
            public_key_info: auto_id.certificate.subject_public_key_info(),
            signature_algorithm,
            data: signing_data.encode(),
            signature,
        };

        verify_signature(req).ok_or(Error::<T>::InvalidSignature)?;
        Ok(())
    }

    fn do_revoke_certificate(
        auto_id_identifier: Identifier,
        signature: Signature,
    ) -> DispatchResult {
        let auto_id = AutoIds::<T>::get(auto_id_identifier).ok_or(Error::<T>::UnknownAutoId)?;

        let (issuer_id, mut issuer_auto_id) = match auto_id.certificate.issuer_id() {
            Some(issuer_id) => (
                issuer_id,
                AutoIds::<T>::get(issuer_id).ok_or(Error::<T>::UnknownIssuer)?,
            ),
            // self revoke
            None => (auto_id_identifier, auto_id.clone()),
        };

        ensure!(
            !CertificateRevocationList::<T>::get(issuer_id).map_or(false, |serials| {
                serials.iter().any(|s| {
                    *s == auto_id.certificate.serial() || *s == issuer_auto_id.certificate.serial()
                })
            }),
            Error::<T>::CertificateAlreadyRevoked
        );

        Self::do_verify_signature(
            &issuer_auto_id,
            CertificateAction {
                id: auto_id_identifier,
                nonce: issuer_auto_id.certificate.nonce(),
                action_type: CertificateActionType::RevokeCertificate,
            },
            signature,
        )?;

        CertificateRevocationList::<T>::mutate(issuer_id, |serials| {
            serials
                .get_or_insert_with(BTreeSet::new)
                .insert(auto_id.certificate.serial());
        });

        issuer_auto_id.certificate.inc_nonce::<T>()?;
        AutoIds::<T>::insert(issuer_id, issuer_auto_id);

        Self::deposit_event(Event::<T>::CertificateRevoked(auto_id_identifier));
        Ok(())
    }

    fn do_deactivate_auto_id(
        auto_id_identifier: Identifier,
        signature: Signature,
    ) -> DispatchResult {
        let auto_id = AutoIds::<T>::get(auto_id_identifier).ok_or(Error::<T>::UnknownIssuer)?;
        Self::do_verify_signature(
            &auto_id,
            CertificateAction {
                id: auto_id_identifier,
                nonce: auto_id.certificate.nonce(),
                action_type: CertificateActionType::DeactivateAutoId,
            },
            signature,
        )?;

        // TODO: remove all the AutoIds registered using leaf certificates if this is the issuer.
        AutoIds::<T>::remove(auto_id_identifier);

        Self::deposit_event(Event::<T>::AutoIdDeactivated(auto_id_identifier));
        Ok(())
    }
}
