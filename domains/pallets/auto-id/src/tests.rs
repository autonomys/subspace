use crate::pallet::AutoIds;
use crate::{
    self as pallet_auto_id, Certificate, CertificateAction, CertificateActionType,
    CertificateRevocationList, Error, Identifier, Pallet, RegisterAutoId, RegisterAutoIdX509,
    RenewAutoId, RenewX509Certificate, Signature, X509Certificate,
};
use alloc::collections::BTreeSet;
use frame_support::assert_noop;
use frame_support::dispatch::RawOrigin;
use frame_support::traits::{ConstU16, ConstU32, ConstU64, Time};
use parity_scale_codec::Encode;
use pem::parse;
use ring::rand::SystemRandom;
use ring::signature::RsaKeyPair;
use sp_auto_id::{DerVec, Validity};
use sp_core::bytes::to_hex;
use sp_core::{H256, U256, blake2_256};
use sp_runtime::BuildStorage;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use std::sync::Arc;
use subspace_runtime_primitives::{DomainEventSegmentSize, Moment};
use x509_parser::der_parser::asn1_rs::ToDer;
use x509_parser::oid_registry::OID_PKCS1_SHA256WITHRSA;
use x509_parser::prelude::{AlgorithmIdentifier, FromDer};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub struct Test {
        System: frame_system,
        AutoId: pallet_auto_id,
        Timestamp: pallet_timestamp,
    }
);

pub struct MockTime;
impl Time for MockTime {
    type Moment = Moment;

    fn now() -> Self::Moment {
        // July 1, 2024, in milliseconds since Epoch
        1_719_792_000_000
    }
}

impl pallet_auto_id::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Time = MockTime;
    type Weights = ();
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ();
    type WeightInfo = ();
}

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type RuntimeTask = RuntimeTask;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
    type MaxConsumers = ConstU32<16>;
    type ExtensionsWeightInfo = ();
    type EventSegmentSize = DomainEventSegmentSize;
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    let mut ext: sp_io::TestExternalities = t.into();
    ext.register_extension(sp_auto_id::host_functions::HostFunctionExtension::new(
        Arc::new(sp_auto_id::host_functions::HostFunctionsImpl),
    ));
    ext
}

/// Converts Algorithm identifier to Der since x509 does not implement the ToDer :(.
fn algorithm_to_der(algorithm_identifier: AlgorithmIdentifier) -> DerVec {
    let sequence_tag: u8 = 0x30;
    let sequence_content = {
        let mut temp = Vec::new();
        temp.extend(algorithm_identifier.algorithm.to_der_vec().unwrap());
        temp.extend(algorithm_identifier.parameters.to_der_vec().unwrap());
        temp
    };
    let encoded_sequence_length = {
        let content_length = sequence_content.len();
        if content_length > 127 {
            // This is long form length encoding
            let length_as_bytes = content_length.to_be_bytes();
            let mut encoded = Vec::with_capacity(length_as_bytes.len() + 1);
            // Set first bit to 1 and store number of length-bytes.
            encoded.push(0x80 | (length_as_bytes.len() as u8));
            encoded.extend_from_slice(&length_as_bytes);
            encoded
        } else {
            // The short form (single-byte length) can be used.
            vec![content_length as u8]
        }
    };

    let mut d = Vec::new();
    d.push(sequence_tag);
    d.extend(encoded_sequence_length);
    d.extend(sequence_content);
    let (_, derived) = AlgorithmIdentifier::from_der(&d).unwrap();
    assert_eq!(algorithm_identifier, derived);
    d.into()
}

fn identifier_from_x509_cert(
    issuer_id: Option<Identifier>,
    cert: &x509_parser::prelude::X509Certificate<'_>,
) -> Identifier {
    let subject_common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .attr_value()
        .as_bytes()
        .to_vec();

    if let Some(issuer_id) = issuer_id {
        let mut data = issuer_id.to_fixed_bytes().to_vec();
        data.extend(subject_common_name);

        blake2_256(&data).into()
    } else {
        blake2_256(&subject_common_name).into()
    }
}

fn register_issuer_auto_id() -> Identifier {
    let issuer_cert = include_bytes!("../res/issuer.cert.der").to_vec();
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&issuer_cert).unwrap();
    let auto_id_identifier = identifier_from_x509_cert(None, &cert);

    Pallet::<Test>::register_auto_id(
        RawOrigin::Signed(1).into(),
        RegisterAutoId::X509(RegisterAutoIdX509::Root {
            certificate: cert.tbs_certificate.as_ref().to_vec().into(),
            signature_algorithm: algorithm_to_der(cert.signature_algorithm.clone()),
            signature: cert.signature_value.as_ref().to_vec(),
        }),
    )
    .unwrap();

    assert_eq!(
        AutoIds::<Test>::get(auto_id_identifier)
            .unwrap()
            .certificate
            .subject_common_name(),
        cert.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .attr_value()
            .as_bytes()
            .to_vec()
    );

    auto_id_identifier
}

fn renew_issuer_auto_id(auto_id_identifier: Identifier) {
    let issuer_cert = include_bytes!("../res/updated.issuer.cert.der").to_vec();
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&issuer_cert).unwrap();
    assert_eq!(auto_id_identifier, identifier_from_x509_cert(None, &cert));

    Pallet::<Test>::renew_auto_id(
        RawOrigin::Signed(1).into(),
        auto_id_identifier,
        RenewAutoId::X509(RenewX509Certificate {
            issuer_id: None,
            certificate: cert.tbs_certificate.as_ref().to_vec().into(),
            signature_algorithm: algorithm_to_der(cert.signature_algorithm.clone()),
            signature: cert.signature_value.as_ref().to_vec(),
        }),
    )
    .unwrap();

    assert_eq!(
        AutoIds::<Test>::get(auto_id_identifier)
            .unwrap()
            .certificate
            .subject_common_name(),
        cert.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .attr_value()
            .as_bytes()
            .to_vec()
    );
}

fn renew_leaf_auto_id(auto_id_identifier: Identifier, issuer_id: Identifier) {
    let issuer_cert = include_bytes!("../res/updated.leaf.cert.der").to_vec();
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&issuer_cert).unwrap();
    assert_eq!(
        auto_id_identifier,
        identifier_from_x509_cert(Some(issuer_id), &cert)
    );

    Pallet::<Test>::renew_auto_id(
        RawOrigin::Signed(1).into(),
        auto_id_identifier,
        RenewAutoId::X509(RenewX509Certificate {
            issuer_id: Some(issuer_id),
            certificate: cert.tbs_certificate.as_ref().to_vec().into(),
            signature_algorithm: algorithm_to_der(cert.signature_algorithm.clone()),
            signature: cert.signature_value.as_ref().to_vec(),
        }),
    )
    .unwrap();

    assert_eq!(
        AutoIds::<Test>::get(auto_id_identifier)
            .unwrap()
            .certificate
            .subject_common_name(),
        cert.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .attr_value()
            .as_bytes()
            .to_vec()
    );
}

fn register_leaf_auto_id(issuer_auto_id: Identifier) -> Identifier {
    let cert = include_bytes!("../res/leaf.cert.der").to_vec();
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&cert).unwrap();
    let auto_id_identifier = identifier_from_x509_cert(Some(issuer_auto_id), &cert);

    Pallet::<Test>::register_auto_id(
        RawOrigin::Signed(1).into(),
        RegisterAutoId::X509(RegisterAutoIdX509::Leaf {
            issuer_id: issuer_auto_id,
            certificate: cert.tbs_certificate.as_ref().to_vec().into(),
            signature_algorithm: algorithm_to_der(cert.signature_algorithm.clone()),
            signature: cert.signature_value.as_ref().to_vec(),
        }),
    )
    .unwrap();

    assert_eq!(
        AutoIds::<Test>::get(auto_id_identifier)
            .unwrap()
            .certificate
            .subject_common_name(),
        cert.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .attr_value()
            .as_bytes()
            .to_vec()
    );

    auto_id_identifier
}

fn sign_preimage(data: Vec<u8>, issuer: bool) -> Signature {
    let priv_key_pem = if issuer {
        include_str!("../res/private.issuer.pem")
    } else {
        include_str!("../res/private.leaf.pem")
    };
    let priv_key_der = parse(priv_key_pem).unwrap().contents().to_vec();
    let rsa_key_pair = RsaKeyPair::from_pkcs8(&priv_key_der).unwrap();
    let mut signature = vec![0; rsa_key_pair.public().modulus_len()];
    let rng = SystemRandom::new();
    rsa_key_pair
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &rng,
            &data,
            &mut signature,
        )
        .unwrap();
    let algo = AlgorithmIdentifier {
        algorithm: OID_PKCS1_SHA256WITHRSA,
        parameters: None,
    };
    Signature {
        signature_algorithm: algorithm_to_der(algo),
        value: signature,
    }
}

#[test]
fn test_register_issuer_auto_id() {
    new_test_ext().execute_with(|| {
        register_issuer_auto_id();
    })
}

#[test]
fn test_register_leaf_auto_id() {
    new_test_ext().execute_with(|| {
        let issuer_id = register_issuer_auto_id();
        register_leaf_auto_id(issuer_id);
    })
}

#[test]
fn test_register_issuer_auto_id_duplicate() {
    new_test_ext().execute_with(|| {
        register_issuer_auto_id();

        let issuer_cert = include_bytes!("../res/issuer.cert.der").to_vec();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&issuer_cert).unwrap();

        // try to register auto id with the same common name
        assert_noop!(
            Pallet::<Test>::register_auto_id(
                RawOrigin::Signed(1).into(),
                RegisterAutoId::X509(RegisterAutoIdX509::Root {
                    certificate: cert.tbs_certificate.as_ref().to_vec().into(),
                    signature_algorithm: algorithm_to_der(cert.signature_algorithm),
                    signature: cert.signature_value.as_ref().to_vec(),
                }),
            ),
            Error::<Test>::AutoIdIdentifierAlreadyExists
        );
    })
}

#[test]
fn test_renew_issuer_auto_id() {
    new_test_ext().execute_with(|| {
        let auto_id_identifier = register_issuer_auto_id();
        renew_issuer_auto_id(auto_id_identifier);
    })
}

#[test]
fn test_renew_leaf_auto_id() {
    new_test_ext().execute_with(|| {
        let issuer_id = register_issuer_auto_id();
        let auto_id_identifier = register_leaf_auto_id(issuer_id);
        renew_leaf_auto_id(auto_id_identifier, issuer_id)
    })
}

#[test]
fn test_self_revoke_certificate() {
    new_test_ext().execute_with(|| {
        let auto_id_identifier = register_issuer_auto_id();
        let auto_id = AutoIds::<Test>::get(auto_id_identifier).unwrap();
        assert!(!CertificateRevocationList::<Test>::contains_key(
            auto_id_identifier
        ));
        let signing_data = CertificateAction {
            id: auto_id_identifier,
            nonce: auto_id.certificate.nonce(),
            action_type: CertificateActionType::RevokeCertificate,
        };
        let signature = sign_preimage(signing_data.encode(), true);
        Pallet::<Test>::revoke_certificate(
            RawOrigin::Signed(1).into(),
            auto_id_identifier,
            signature,
        )
        .unwrap();
        let auto_id = AutoIds::<Test>::get(auto_id_identifier).unwrap();
        assert!(
            CertificateRevocationList::<Test>::get(auto_id_identifier)
                .unwrap()
                .contains(&auto_id.certificate.serial())
        );

        assert_eq!(auto_id.certificate.nonce(), U256::one());

        // try issuing leaf certificate when issuer is revoked
        let cert = include_bytes!("../res/leaf.cert.der").to_vec();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&cert).unwrap();
        let _ = identifier_from_x509_cert(Some(auto_id_identifier), &cert);

        assert_noop!(
            Pallet::<Test>::register_auto_id(
                RawOrigin::Signed(1).into(),
                RegisterAutoId::X509(RegisterAutoIdX509::Leaf {
                    issuer_id: auto_id_identifier,
                    certificate: cert.tbs_certificate.as_ref().to_vec().into(),
                    signature_algorithm: algorithm_to_der(cert.signature_algorithm.clone()),
                    signature: cert.signature_value.as_ref().to_vec(),
                }),
            ),
            Error::<Test>::CertificateRevoked,
        );
    })
}

#[test]
fn test_revoke_leaf_certificate() {
    new_test_ext().execute_with(|| {
        let issuer_id = register_issuer_auto_id();
        let leaf_id = register_leaf_auto_id(issuer_id);
        let issuer_auto_id = AutoIds::<Test>::get(issuer_id).unwrap();
        let leaf_auto_id = AutoIds::<Test>::get(leaf_id).unwrap();

        assert!(!CertificateRevocationList::<Test>::contains_key(issuer_id));

        // leaf tries to revoke itself
        let signing_data = CertificateAction {
            id: leaf_id,
            nonce: issuer_auto_id.certificate.nonce(),
            action_type: CertificateActionType::RevokeCertificate,
        };

        // sign with leaf's private key
        let signature = sign_preimage(signing_data.encode(), false);

        // leaf tries to revoke itself
        assert_noop!(
            Pallet::<Test>::revoke_certificate(RawOrigin::Signed(1).into(), leaf_id, signature),
            Error::<Test>::InvalidSignature
        );

        // now issuer revokes leaf
        let signing_data = CertificateAction {
            id: leaf_id,
            nonce: issuer_auto_id.certificate.nonce(),
            action_type: CertificateActionType::RevokeCertificate,
        };
        let signature = sign_preimage(signing_data.encode(), true);

        Pallet::<Test>::revoke_certificate(RawOrigin::Signed(1).into(), leaf_id, signature)
            .unwrap();

        assert!(
            CertificateRevocationList::<Test>::get(issuer_id)
                .unwrap()
                .contains(&leaf_auto_id.certificate.serial())
        );

        // revoking the same certificate again should fail
        let signing_data = CertificateAction {
            id: leaf_id,
            nonce: issuer_auto_id.certificate.nonce(),
            action_type: CertificateActionType::RevokeCertificate,
        };
        let signature = sign_preimage(signing_data.encode(), true);

        assert_noop!(
            Pallet::<Test>::revoke_certificate(RawOrigin::Signed(1).into(), leaf_id, signature),
            Error::<Test>::CertificateAlreadyRevoked
        );
    })
}

#[test]
fn test_deactivate_auto_id() {
    new_test_ext().execute_with(|| {
        let auto_id_identifier = register_issuer_auto_id();
        let auto_id = AutoIds::<Test>::get(auto_id_identifier).unwrap();
        let signing_data = CertificateAction {
            id: auto_id_identifier,
            nonce: auto_id.certificate.nonce(),
            action_type: CertificateActionType::DeactivateAutoId,
        };
        let signature = sign_preimage(signing_data.encode(), true);
        Pallet::<Test>::deactivate_auto_id(
            RawOrigin::Signed(1).into(),
            auto_id_identifier,
            signature,
        )
        .unwrap();
        assert!(AutoIds::<Test>::get(auto_id_identifier).is_none());
    })
}

#[test]
fn test_auto_id_identifier_is_deterministic() {
    new_test_ext().execute_with(|| {
        let auto_id = crate::AutoId {
            certificate: Certificate::X509(X509Certificate {
                issuer_id: None,
                subject_common_name: b"Test".to_vec(),
                validity: Validity {
                    not_before: 0,
                    not_after: 0,
                },
                subject_public_key_info: DerVec::from(vec![1, 2, 3, 4]),
                nonce: U256::zero(),
                serial: U256::zero(),
                raw: vec![1, 2, 3, 4].into(),
                issued_serials: BTreeSet::new(),
            }),
        };

        let expected_auto_id_identifier =
            "0x8d2143d76615c515b5cc88fa7806aef268edeea87571c8f8b21a19f77b9993ba";
        assert_eq!(
            to_hex(
                &auto_id.certificate.derive_identifier().to_fixed_bytes(),
                true
            ),
            expected_auto_id_identifier
        );

        let auto_id_child = crate::AutoId {
            certificate: Certificate::X509(X509Certificate {
                issuer_id: Some(auto_id.certificate.derive_identifier()),
                subject_common_name: b"child".to_vec(),
                validity: Validity {
                    not_before: 0,
                    not_after: 0,
                },
                subject_public_key_info: DerVec::from(vec![1, 2, 3, 4]),
                nonce: U256::zero(),
                serial: U256::zero(),
                raw: vec![1, 2, 3, 4].into(),
                issued_serials: BTreeSet::new(),
            }),
        };

        let expected_auto_id_child_identifier =
            "0xb273167fb0c55e2df1fcd5c44fcf90e497bd826e2eb4be2f167ff1c46b4d686d";
        assert_eq!(
            to_hex(
                &auto_id_child
                    .certificate
                    .derive_identifier()
                    .to_fixed_bytes(),
                true
            ),
            expected_auto_id_child_identifier
        );
    })
}
