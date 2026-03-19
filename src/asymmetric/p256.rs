// P-256 elliptic curve implementation

use crate::asymmetric::{KeyAgreement, SignatureAlgorithm};
use crate::error::{CryptoKitError, Result};

/// P-256 public key size (uncompressed x + y, 64 bytes)
const P256_PUBLIC_KEY_SIZE: usize = 64;
/// P-256 signature size (r + s, 64 bytes)
const P256_SIGNATURE_SIZE: usize = 64;
/// Maximum size for Secure Enclave data representation
const SE_P256_DATA_REPRESENTATION_MAX_SIZE: usize = 1024;

// P-256 related Swift FFI declarations
extern "C" {
    fn swift_p256_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_p256_sign(
        private_key: *const u8,
        data: *const u8,
        data_len: i32,
        signature: *mut u8,
    ) -> i32;
    fn swift_p256_verify(
        public_key: *const u8,
        signature: *const u8,
        data: *const u8,
        data_len: i32,
    ) -> i32;
    fn swift_p256_key_agreement(
        private_key: *const u8,
        public_key: *const u8,
        shared_secret: *mut u8,
    ) -> i32;

    // Secure Enclave P-256
    fn swift_se_p256_generate_keypair(
        data_representation: *mut u8,
        data_representation_len: *mut usize,
        public_key: *mut u8,
        access_control_mode: i32,
    ) -> i32;
    fn swift_se_p256_get_public_key(
        data_representation: *const u8,
        data_representation_len: usize,
        public_key: *mut u8,
    ) -> i32;
    fn swift_se_p256_sign(
        data_representation: *const u8,
        data_representation_len: usize,
        message: *const u8,
        message_len: usize,
        signature: *mut u8,
        signature_len: *mut usize,
    ) -> i32;
    fn swift_se_p256_delete_key(
        data_representation: *const u8,
        data_representation_len: usize,
    ) -> i32;
    fn swift_se_delete_all_keys() -> i32;
}

/// Delete all Secure Enclave keys belonging to this app from the Keychain.
pub fn se_delete_all_keys() -> Result<()> {
    unsafe {
        let result = swift_se_delete_all_keys();
        if result != 0 {
            return Err(CryptoKitError::InvalidInput(
                "Failed to delete all SE keys".to_string(),
            ));
        }
        Ok(())
    }
}

/// P-256 private key (32 bytes)
#[derive(Clone)]
pub struct P256PrivateKey {
    data: [u8; 32],
}

/// P-256 public key (64 bytes)
#[derive(Clone)]
pub struct P256PublicKey {
    data: [u8; 64],
}

/// P-256 signature (64 bytes)
#[derive(Clone)]
pub struct P256Signature {
    data: [u8; 64],
}

/// P-256 shared secret (32 bytes)
#[derive(Clone)]
pub struct P256SharedSecret {
    data: [u8; 32],
}

impl P256PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

impl P256PublicKey {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.data
    }
}

impl P256Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.data
    }
}

impl P256SharedSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

/// P-256 elliptic curve digital signature algorithm
pub struct P256;

impl SignatureAlgorithm for P256 {
    type PrivateKey = P256PrivateKey;
    type PublicKey = P256PublicKey;
    type Signature = P256Signature;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        unsafe {
            let mut private_key = [0u8; 32];
            let mut public_key = [0u8; 64];

            let result =
                swift_p256_generate_keypair(private_key.as_mut_ptr(), public_key.as_mut_ptr());

            if result == 0 {
                Ok((
                    P256PrivateKey::from_bytes(private_key),
                    P256PublicKey::from_bytes(public_key),
                ))
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }

    fn sign(private_key: &Self::PrivateKey, data: &[u8]) -> Result<Self::Signature> {
        unsafe {
            let mut signature = [0u8; 64];

            let result = swift_p256_sign(
                private_key.as_bytes().as_ptr(),
                data.as_ptr(),
                data.len() as i32,
                signature.as_mut_ptr(),
            );

            if result == 0 {
                Ok(P256Signature::from_bytes(signature))
            } else {
                Err(CryptoKitError::SignatureFailed)
            }
        }
    }

    fn verify(
        public_key: &Self::PublicKey,
        signature: &Self::Signature,
        data: &[u8],
    ) -> Result<bool> {
        unsafe {
            let result = swift_p256_verify(
                public_key.as_bytes().as_ptr(),
                signature.as_bytes().as_ptr(),
                data.as_ptr(),
                data.len() as i32,
            );

            match result {
                1 => Ok(true),
                0 => Ok(false),
                _ => Err(CryptoKitError::VerificationFailed),
            }
        }
    }
}

impl KeyAgreement for P256 {
    type PrivateKey = P256PrivateKey;
    type PublicKey = P256PublicKey;
    type SharedSecret = P256SharedSecret;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        <P256 as SignatureAlgorithm>::generate_key_pair()
    }

    fn key_agreement(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret> {
        unsafe {
            let mut shared_secret = [0u8; 32];

            let result = swift_p256_key_agreement(
                private_key.as_bytes().as_ptr(),
                public_key.as_bytes().as_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result == 0 {
                Ok(P256SharedSecret::from_bytes(shared_secret))
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }
}

// Convenience functions
pub fn generate_keypair() -> Result<(P256PrivateKey, P256PublicKey)> {
    <P256 as SignatureAlgorithm>::generate_key_pair()
}

pub fn sign(private_key: &P256PrivateKey, data: &[u8]) -> Result<P256Signature> {
    P256::sign(private_key, data)
}

pub fn verify(public_key: &P256PublicKey, signature: &P256Signature, data: &[u8]) -> Result<bool> {
    P256::verify(public_key, signature, data)
}

pub fn key_agreement(
    private_key: &P256PrivateKey,
    public_key: &P256PublicKey,
) -> Result<P256SharedSecret> {
    P256::key_agreement(private_key, public_key)
}

// MARK: - Secure Enclave P-256

/// Secure Enclave P-256 private key handle (opaque data representation)
pub struct SEP256PrivateKey {
    data_representation: Vec<u8>,
}

impl SEP256PrivateKey {
    /// Generate a new P-256 key in the Secure Enclave
    ///
    /// `access_control_mode`: 0 = none, 1 = biometry only, 2 = biometry + passcode
    pub fn generate(access_control_mode: i32) -> Result<Self> {
        unsafe {
            let mut data_rep = vec![0u8; SE_P256_DATA_REPRESENTATION_MAX_SIZE];
            let mut data_rep_len: usize = 0;
            let mut public_key_bytes = vec![0u8; P256_PUBLIC_KEY_SIZE];

            let result = swift_se_p256_generate_keypair(
                data_rep.as_mut_ptr(),
                &mut data_rep_len,
                public_key_bytes.as_mut_ptr(),
                access_control_mode,
            );

            if result == -2 {
                return Err(CryptoKitError::InvalidInput(
                    "SecAccessControlCreateWithFlags returned nil".to_string(),
                ));
            }
            if result == -3 {
                let err_msg =
                    String::from_utf8_lossy(&data_rep[..data_rep_len]).to_string();
                return Err(CryptoKitError::InvalidInput(err_msg));
            }
            if result != 0 {
                return Err(CryptoKitError::KeyGenerationFailed);
            }

            data_rep.truncate(data_rep_len);

            Ok(SEP256PrivateKey {
                data_representation: data_rep,
            })
        }
    }

    pub fn public_key(&self) -> Result<P256PublicKey> {
        unsafe {
            let mut public_key_bytes = vec![0u8; P256_PUBLIC_KEY_SIZE];

            let result = swift_se_p256_get_public_key(
                self.data_representation.as_ptr(),
                self.data_representation.len(),
                public_key_bytes.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::KeyGenerationFailed);
            }

            let mut pk = [0u8; P256_PUBLIC_KEY_SIZE];
            pk.copy_from_slice(&public_key_bytes);
            Ok(P256PublicKey::from_bytes(pk))
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<P256Signature> {
        unsafe {
            let mut signature = vec![0u8; P256_SIGNATURE_SIZE];
            let mut signature_len = P256_SIGNATURE_SIZE;

            let result = swift_se_p256_sign(
                self.data_representation.as_ptr(),
                self.data_representation.len(),
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                &mut signature_len,
            );

            if result != 0 {
                return Err(CryptoKitError::SigningFailed);
            }

            let mut sig = [0u8; P256_SIGNATURE_SIZE];
            sig.copy_from_slice(&signature[..P256_SIGNATURE_SIZE]);
            Ok(P256Signature::from_bytes(sig))
        }
    }

    /// Opaque data representation for persistence
    pub fn data_representation(&self) -> &[u8] {
        &self.data_representation
    }

    /// Restore from persisted data representation
    pub fn from_data_representation(data: &[u8]) -> Self {
        SEP256PrivateKey {
            data_representation: data.to_vec(),
        }
    }

    /// Delete this key from the Secure Enclave / Keychain
    pub fn delete(&self) -> Result<()> {
        unsafe {
            let result = swift_se_p256_delete_key(
                self.data_representation.as_ptr(),
                self.data_representation.len(),
            );

            if result != 0 {
                return Err(CryptoKitError::InvalidInput(
                    "Failed to delete SE P256 key".to_string(),
                ));
            }

            Ok(())
        }
    }
}
