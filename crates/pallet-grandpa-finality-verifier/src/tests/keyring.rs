//! Utilities for working with test accounts.

use codec::Encode;
use ed25519_dalek::{
    SecretKey, Signature, Signer, SigningKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use finality_grandpa::voter_set::VoterSet;
use sp_consensus_grandpa::{AuthorityId, AuthorityList, AuthorityWeight};
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
    pub(crate) fn public(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.signing_key().to_keypair_bytes()[SECRET_KEY_LENGTH..][..PUBLIC_KEY_LENGTH]
            .try_into()
            .unwrap()
    }

    pub(crate) fn signing_key(&self) -> SigningKey {
        let data = self.0.encode();
        let mut secret_key: SecretKey = [0_u8; 32];
        secret_key[0..data.len()].copy_from_slice(&data);

        SigningKey::from_bytes(&secret_key)
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key().sign(msg)
    }
}

impl From<Account> for AuthorityId {
    #[inline]
    fn from(p: Account) -> Self {
        sp_application_crypto::UncheckedFrom::unchecked_from(p.public())
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
    (0..len).map(Account).collect()
}
