//! Utilities for working with test accounts.

use codec::Encode;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
use finality_grandpa::voter_set::VoterSet;
use sp_finality_grandpa::{AuthorityId, AuthorityList, AuthorityWeight};
use sp_std::prelude::*;

/// Set of test accounts with friendly names.
pub(crate) const ALICE: Account = Account(0);
pub(crate) const BOB: Account = Account(1);
pub(crate) const CHARLIE: Account = Account(2);
pub(crate) const DAVE: Account = Account(3);
pub(crate) const EVE: Account = Account(4);

/// A test account which can be used to sign messages.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Account(pub u16);

impl Account {
    pub(crate) fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret())
    }

    pub(crate) fn secret(&self) -> SecretKey {
        let data = self.0.encode();
        let mut bytes = [0_u8; 32];
        bytes[0..data.len()].copy_from_slice(&*data);
        SecretKey::from_bytes(&bytes)
            .expect("A static array of the correct length is a known good.")
    }

    pub(crate) fn pair(&self) -> Keypair {
        let mut pair: [u8; 64] = [0; 64];

        let secret = self.secret();
        pair[..32].copy_from_slice(&secret.to_bytes());

        let public = self.public();
        pair[32..].copy_from_slice(&public.to_bytes());

        Keypair::from_bytes(&pair)
            .expect("We expect the SecretKey to be good, so this must also be good.")
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        self.pair().sign(msg)
    }
}

impl From<Account> for AuthorityId {
    fn from(p: Account) -> Self {
        sp_application_crypto::UncheckedFrom::unchecked_from(p.public().to_bytes())
    }
}

/// Get a valid set of voters for a Grandpa round.
pub(crate) fn voter_set() -> VoterSet<AuthorityId> {
    VoterSet::new(authority_list()).unwrap()
}

/// Convenience function to get a list of Grandpa authorities.
pub(crate) fn authority_list() -> AuthorityList {
    test_keyring()
        .iter()
        .map(|(id, w)| (AuthorityId::from(*id), *w))
        .collect()
}

/// Get the corresponding identities from the keyring for the "standard" authority set.
pub(crate) fn test_keyring() -> Vec<(Account, AuthorityWeight)> {
    vec![(ALICE, 1), (BOB, 1), (CHARLIE, 1)]
}

/// Get a list of "unique" accounts.
pub(crate) fn accounts(len: u16) -> Vec<Account> {
    (0..len).into_iter().map(Account).collect()
}
