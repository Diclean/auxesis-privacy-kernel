//! AES-256-GCM sealing and unsealing of the vault's records and manifest.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use zeroize::Zeroizing;

use super::key::random;
use super::{Vault, VaultError, MAGIC, NONCE_LEN, TAG_LEN};

impl Vault {
    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new((&*self.key).into())
    }

    pub(super) fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        random(&mut nonce)?;
        self.seal_with_nonce(aad, plaintext, &nonce)
    }

    fn seal_with_nonce(
        &self,
        aad: &[u8],
        plaintext: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>, VaultError> {
        let ciphertext = self
            .cipher()
            .encrypt(
                nonce.into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| VaultError::Corrupt("seal failed"))?;
        let mut sealed = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(nonce);
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
        let nonce: &[u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| VaultError::Corrupt("not a complete vault record"))?;
        let plaintext = self
            .cipher()
            .decrypt(
                nonce.into(),
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

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use crate::vault::paths::{additional_data, hex};

    #[test]
    fn old_version_vector_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault {
            home: kernel_core::SandboxHome::open(dir.path()).unwrap(),
            key: Zeroizing::new([7; 32]),
        };
        let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let aad = additional_data("manifest");
        let plaintext = b"fixed vault plaintext\0v1";
        // Produced with aes-gcm 0.10.3 on main: magic, nonce, ciphertext, tag.
        const OLD_HEX: &str = "41585641554c5431000102030405060708090a0b7ee891157929af2802de91bc92340d938f48d3f66c620100dbd695992844a46fc6a32fef441e9bc0";
        let old_blob: Vec<u8> = OLD_HEX
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(aad, b"AXVAULT1manifest");
        assert_eq!(&vault.unseal(&aad, &old_blob).unwrap()[..], plaintext);
        let sealed = vault.seal_with_nonce(&aad, plaintext, &nonce).unwrap();
        assert_eq!(sealed, old_blob);
        assert_eq!(hex(&sealed), OLD_HEX);
        assert!(vault.unseal(b"AXVAULT1wrong", &old_blob).is_err());
        let mut tampered = old_blob;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(vault.unseal(&aad, &tampered).is_err());
    }
}
