//! AES-256-GCM sealing and unsealing of the vault's records and manifest.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use zeroize::Zeroizing;

use super::key::random;
use super::{Vault, VaultError, MAGIC, NONCE_LEN, TAG_LEN};

impl Vault {
    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key[..]))
    }

    pub(super) fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        random(&mut nonce)?;
        let ciphertext = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| VaultError::Corrupt("seal failed"))?;
        let mut sealed = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    pub(super) fn unseal(
        &self,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if sealed.len() < MAGIC.len() + NONCE_LEN + TAG_LEN || !sealed.starts_with(MAGIC) {
            return Err(VaultError::Corrupt("not a complete vault record"));
        }
        let (nonce, ciphertext) = sealed[MAGIC.len()..].split_at(NONCE_LEN);
        let plaintext = self
            .cipher()
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| {
                VaultError::Corrupt("authentication failed: wrong key, tampered, or moved")
            })?;
        Ok(Zeroizing::new(plaintext))
    }
}
