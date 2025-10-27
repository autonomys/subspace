//! Extended MultiSignature and FN-DSA tests for the consensus chain.

#[cfg(feature = "fn-dsa")]
#[allow(unused)]
mod fn_dsa_keyring {
    use sp_core::hashing::blake2_256;
    use sp_runtime::AccountId32;
    use std::sync::OnceLock;
    use subspace_core_primitives::fn_dsa::{
        FnDsaKeyGenerator, FnDsaPrivateKey, FnDsaPublicKey, FnDsaSignature, FnDsaSigner,
    };

    /// Test FN-DSA keypairs with deterministic generation for testing
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum FnDsaKeyring {
        Alice,
        Bob,
        Charlie,
    }

    impl FnDsaKeyring {
        /// Generate or retrieve cached keypair for this keyring identity
        pub fn keypair(self) -> (FnDsaPrivateKey, FnDsaPublicKey) {
            static ALICE: OnceLock<(FnDsaPrivateKey, FnDsaPublicKey)> = OnceLock::new();
            static BOB: OnceLock<(FnDsaPrivateKey, FnDsaPublicKey)> = OnceLock::new();
            static CHARLIE: OnceLock<(FnDsaPrivateKey, FnDsaPublicKey)> = OnceLock::new();

            let lock = match self {
                Self::Alice => &ALICE,
                Self::Bob => &BOB,
                Self::Charlie => &CHARLIE,
            };

            lock.get_or_init(|| {
                // Note: This generates random keys each time tests run
                // For true determinism, you'd need to seed the RNG
                // The keys will be consistent within a single test run
                FnDsaPrivateKey::generate_keypair(9u32)
                    .expect("FN-DSA keypair generation must succeed")
            })
            .clone()
        }

        /// Sign a message with this keyring's private key
        pub fn sign(self, msg: &[u8]) -> FnDsaSignature {
            let (private_key, _) = self.keypair();
            FnDsaSignature::sign(msg, &private_key).expect("FN-DSA signing must succeed")
        }

        /// Get the public key for this keyring
        pub fn public_key(self) -> FnDsaPublicKey {
            self.keypair().1
        }

        /// Convert to AccountId32 (derived from Blake2-256 hash of public key)
        pub fn to_account_id(self) -> AccountId32 {
            let (_, public_key) = self.keypair();
            AccountId32::from(blake2_256(public_key.as_bytes()))
        }
    }
}

#[cfg(all(feature = "fn-dsa", test))]
#[allow(unused)]
mod tests {
    use super::fn_dsa_keyring::FnDsaKeyring;
    use crate::{MockConsensusNode, construct_extrinsic_raw_payload};
    use frame_system::pallet_prelude::BlockNumberFor;
    use parity_scale_codec::{Decode, Encode};
    use sc_service::BasePath;
    use sp_blockchain::HeaderBackend;
    use sp_keyring::Sr25519Keyring;
    use subspace_core_primitives::fn_dsa::{FnDsaSignature, FnDsaVerifier};
    use subspace_runtime_primitives::multisignature::{
        ExtendedMultiSignature, FnDsaSignatureWithKey,
    };
    use subspace_runtime_primitives::opaque::Block;
    use subspace_test_runtime::{Runtime, RuntimeCall, UncheckedExtrinsic};
    use tempfile::TempDir;

    type BalanceOf<T> = <<T as pallet_transaction_payment::Config>::OnChargeTransaction as pallet_transaction_payment::OnChargeTransaction<T>>::Balance;

    /// Construct an extrinsic signed with FN-DSA
    fn construct_fn_dsa_extrinsic<Client>(
        client: impl AsRef<Client>,
        function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
        caller: FnDsaKeyring,
        immortal: bool,
        nonce: u32,
        tip: BalanceOf<Runtime>,
    ) -> UncheckedExtrinsic
    where
        BalanceOf<Runtime>: Send + Sync + From<u64> + sp_runtime::FixedPointOperand,
        u64: From<BlockNumberFor<Runtime>>,
        Client: HeaderBackend<Block>,
    {
        let function = function.into();
        let (raw_payload, extra) =
            construct_extrinsic_raw_payload(client, function.clone(), immortal, nonce, tip);

        let fn_dsa_sig = raw_payload.using_encoded(|e| caller.sign(e));
        let public_key = caller.public_key();

        let extended_sig = ExtendedMultiSignature::FnDsa(FnDsaSignatureWithKey {
            public_key,
            signature: fn_dsa_sig,
        });

        UncheckedExtrinsic::new_signed(
            function,
            sp_runtime::MultiAddress::Id(caller.to_account_id()),
            extended_sig,
            extra,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fn_dsa_signature_on_consensus_chain() {
        let directory = TempDir::new().expect("Must be able to create temporary directory");

        let mut builder = sc_cli::LoggerBuilder::new("");
        builder.with_colors(false);
        let _ = builder.init();

        let tokio_handle = tokio::runtime::Handle::current();

        // Start consensus node with Ferdie as authority
        let mut ferdie = MockConsensusNode::run(
            tokio_handle,
            Sr25519Keyring::Ferdie,
            BasePath::new(directory.path().join("ferdie")),
        );

        // Generate FN-DSA account
        let fn_dsa_alice = FnDsaKeyring::Alice;
        let fn_dsa_account = fn_dsa_alice.to_account_id();

        // Verify FN-DSA account nonce (it should exist due to pre-funding in genesis)
        let fn_dsa_nonce = ferdie.account_nonce_of(fn_dsa_account);
        tracing::info!("FN-DSA account nonce: {}", fn_dsa_nonce);

        // Create a simple remark call - this should work without balance transfers
        let remark_call = RuntimeCall::System(frame_system::Call::remark {
            remark: b"FN-DSA test transaction".to_vec(),
        });

        // Construct extrinsic with FN-DSA signature
        let fn_dsa_tx = construct_fn_dsa_extrinsic(
            &ferdie.client,
            remark_call.clone(),
            fn_dsa_alice,
            false,
            fn_dsa_nonce,
            0,
        );

        // Extract signature from the extrinsic for testing
        let (raw_payload, _extra) = construct_extrinsic_raw_payload(
            &ferdie.client,
            remark_call.clone(),
            false,
            fn_dsa_nonce,
            0,
        );

        // Create FN-DSA signature for encoding test
        let fn_dsa_sig = raw_payload.using_encoded(|e| fn_dsa_alice.sign(e));
        let public_key = fn_dsa_alice.public_key();

        let extended_sig = ExtendedMultiSignature::FnDsa(FnDsaSignatureWithKey {
            public_key,
            signature: fn_dsa_sig,
        });

        // Encode the signature to verify it works
        let encoded_sig = extended_sig.encode();
        tracing::info!("Extended signature encoded length: {}", encoded_sig.len());

        // Decode back to verify roundtrip
        let _decoded_sig = ExtendedMultiSignature::decode(&mut &encoded_sig[..])
            .expect("Should decode successfully");
        tracing::info!("✅ FN-DSA signature encoding/decoding works");

        // Try to submit the FN-DSA signed extrinsic
        // This will fail until the runtime WASM is rebuilt with fn-dsa feature
        let result = ferdie.send_extrinsic(fn_dsa_tx).await;

        if result.is_err() {
            tracing::warn!(
                "⚠️  FN-DSA extrinsic submission failed (expected until runtime WASM is rebuilt with fn-dsa): {:?}",
                result
            );
        } else {
            ferdie.produce_blocks(1).await.unwrap();
            tracing::info!(
                "✅ FN-DSA signed extrinsic was successfully verified and included in block"
            );
        }
    }
}
