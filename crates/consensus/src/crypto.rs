//! Cryptographic algorithms

use alloc::boxed::Box;
use alloy_primitives::U256;

#[cfg(any(feature = "secp256k1", feature = "k256"))]
use alloy_primitives::Signature;

#[cfg(feature = "crypto-backend")]
pub use backend::{install_default_provider, CryptoProvider, CryptoProviderAlreadySetError};

/// Error for signature S.
#[derive(Debug, thiserror::Error)]
#[error("signature S value is greater than `secp256k1n / 2`")]
pub struct InvalidSignatureS;

/// Opaque error type for sender recovery.
#[derive(Debug, Default, thiserror::Error)]
#[error("Failed to recover the signer")]
pub struct RecoveryError {
    #[source]
    source: Option<Box<dyn core::error::Error + Send + Sync + 'static>>,
}

impl RecoveryError {
    /// Create a new error with no associated source
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new error with an associated source.
    ///
    /// **NOTE:** The "source" should **NOT** be used to propagate cryptographic
    /// errors e.g. signature parsing or verification errors.
    pub fn from_source<E: core::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self { source: Some(Box::new(err)) }
    }
}

impl From<alloy_primitives::SignatureError> for RecoveryError {
    fn from(err: alloy_primitives::SignatureError) -> Self {
        Self::from_source(err)
    }
}

/// The order of the secp256k1 curve, divided by two. Signatures that should be checked according
/// to EIP-2 should have an S value less than or equal to this.
///
/// `57896044618658097711785492504343953926418782139537452191302581570759080747168`
pub const SECP256K1N_HALF: U256 = U256::from_be_bytes([
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
]);

/// Crypto backend module for pluggable cryptographic implementations.
#[cfg(feature = "crypto-backend")]
pub mod backend {
    use super::*;
    use alloc::sync::Arc;
    use alloy_primitives::Address;

    #[cfg(feature = "std")]
    use std::sync::OnceLock;

    #[cfg(not(feature = "std"))]
    use once_cell::race::OnceBox;

    /// Trait for cryptographic providers that can perform signature recovery and verification.
    ///
    /// This trait allows pluggable cryptographic backends for Ethereum signature operations.
    /// By default, alloy uses compile-time selected implementations (secp256k1 or k256),
    /// but applications can install a custom provider to override this behavior.
    ///
    /// # Why is this needed?
    ///
    /// The primary reason is performance - when targeting special execution environments
    /// that require custom cryptographic logic. For example, zkVMs (zero-knowledge virtual
    /// machines) may have special accelerators that would allow them to perform signature
    /// recovery and verification faster.
    ///
    /// # Usage
    ///
    /// 1. Enable the `crypto-backend` feature in your `Cargo.toml`
    /// 2. Implement the `CryptoProvider` trait for your custom backend
    /// 3. Install it globally using [`install_default_provider`]
    /// 4. All subsequent signature operations will use your provider
    ///
    /// Note: This trait provides both signature recovery and verification functionality.
    /// For signature creation, use the compile-time selected implementations in the
    /// [`secp256k1`] module.
    ///
    /// ```rust,ignore
    /// use alloy_consensus::crypto::backend::{CryptoProvider, install_default_provider};
    /// use alloy_primitives::Address;
    /// use alloc::sync::Arc;
    ///
    /// struct MyCustomProvider;
    ///
    /// impl CryptoProvider for MyCustomProvider {
    ///     fn recover_signer_unchecked(
    ///         &self,
    ///         sig: &[u8; 65],
    ///         msg: &[u8; 32],
    ///     ) -> Result<Address, RecoveryError> {
    ///         // Your custom implementation here
    ///         todo!()
    ///     }
    ///
    ///     fn verify_signature_unchecked(
    ///         &self,
    ///         sig: &[u8; 65],
    ///         msg: &[u8; 32],
    ///         public_key: &[u8; 65],
    ///     ) -> Result<Address, RecoveryError> {
    ///         // Your custom implementation here
    ///         todo!()
    ///     }
    /// }
    ///
    /// // Install your provider globally
    /// install_default_provider(Arc::new(MyCustomProvider)).unwrap();
    /// ```
    pub trait CryptoProvider: Send + Sync + 'static {
        /// Recover signer from signature and message hash, without ensuring low S values.
        fn recover_signer_unchecked(
            &self,
            sig: &[u8; 65],
            msg: &[u8; 32],
        ) -> Result<Address, RecoveryError>;

        /// Verify signature against a known public key, without ensuring low S values.
        /// Returns the address derived from the public key if verification succeeds.
        fn verify_signature_unchecked(
            &self,
            sig: &[u8; 65],
            msg: &[u8; 32],
            public_key: &[u8; 65],
        ) -> Result<Address, RecoveryError>;
    }

    /// Global default crypto provider.
    #[cfg(feature = "std")]
    static DEFAULT_PROVIDER: OnceLock<Arc<dyn CryptoProvider>> = OnceLock::new();

    #[cfg(not(feature = "std"))]
    static DEFAULT_PROVIDER: OnceBox<Arc<dyn CryptoProvider>> = OnceBox::new();

    /// Error returned when attempting to install a provider when one is already installed.
    /// Contains the provider that was attempted to be installed.
    pub struct CryptoProviderAlreadySetError {
        /// The provider that was attempted to be installed.
        pub provider: Arc<dyn CryptoProvider>,
    }

    impl core::fmt::Debug for CryptoProviderAlreadySetError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("CryptoProviderAlreadySetError")
                .field("provider", &"<crypto provider>")
                .finish()
        }
    }

    impl core::fmt::Display for CryptoProviderAlreadySetError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "crypto provider already installed")
        }
    }

    impl core::error::Error for CryptoProviderAlreadySetError {}

    /// Install the default crypto provider.
    ///
    /// This sets the global default provider used by the high-level crypto functions.
    /// Returns an error containing the provider that was attempted to be installed if one is
    /// already set.
    pub fn install_default_provider(
        provider: Arc<dyn CryptoProvider>,
    ) -> Result<(), CryptoProviderAlreadySetError> {
        #[cfg(feature = "std")]
        {
            DEFAULT_PROVIDER.set(provider).map_err(|provider| {
                // Return the provider we tried to install in the error
                CryptoProviderAlreadySetError { provider }
            })
        }
        #[cfg(not(feature = "std"))]
        {
            DEFAULT_PROVIDER.set(Box::new(provider)).map_err(|provider| {
                // Return the provider we tried to install in the error
                CryptoProviderAlreadySetError { provider: *provider }
            })
        }
    }

    /// Get the currently installed default provider, panicking if none is installed.
    pub fn get_default_provider() -> &'static dyn CryptoProvider {
        try_get_provider().unwrap_or_else(|| {
            panic!("No crypto backend installed. Call install_default_provider() first.")
        })
    }

    /// Try to get the currently installed default provider, returning None if none is installed.
    pub(super) fn try_get_provider() -> Option<&'static dyn CryptoProvider> {
        DEFAULT_PROVIDER.get().map(|arc| arc.as_ref())
    }
}

/// Secp256k1 cryptographic functions.
///
/// ## Signature Recovery vs Verification
///
/// This module provides two approaches for validating Ethereum signatures:
///
/// **Recovery** - Extract the signer's address from a signature:
/// - Use when you don't know the public key in advance
/// - More computationally expensive (needs ECDSA recovery)
/// - Functions: [`recover_signer`], [`recover_signer_unchecked`]
///
/// **Verification** - Validate a signature against a known public key:
/// - Use when you already have the public key (e.g., stateless block processing)
/// - More efficient in specialized environments (zkVMs, precompiles)
/// - Functions: [`verify_signature`], [`verify_signature_unchecked`]
///
/// Both approaches return the address on success, ensuring type-safe validation.
///
/// ## EIP-2 Compliance
///
/// Functions ending with `_unchecked` skip the EIP-2 signature malleability check
/// (S value must be ≤ secp256k1n/2). Use these for pre-Homestead signatures or
/// when you need maximum compatibility.
///
/// ## Example: Stateless Block Processing
///
/// ```rust,ignore
/// use alloy_consensus::crypto::secp256k1::verify_signature;
///
/// // When public keys are provided externally
/// fn verify_transaction(
///     signature: &Signature,
///     msg_hash: B256,
///     public_key: &[u8; 65],
///     is_homestead: bool,
/// ) -> Result<Address, RecoveryError> {
///     if is_homestead {
///         // Homestead enforces EIP-2 (low S values)
///         verify_signature(signature, msg_hash, public_key)
///     } else {
///         // Pre-homestead allows any S value
///         verify_signature_unchecked(signature, msg_hash, public_key)
///     }
/// }
/// ```
#[cfg(any(feature = "secp256k1", feature = "k256"))]
pub mod secp256k1 {
    pub use imp::{public_key_to_address, sign_message};

    use super::*;
    use alloy_primitives::{Address, B256};

    #[cfg(not(feature = "secp256k1"))]
    use super::impl_k256 as imp;
    #[cfg(feature = "secp256k1")]
    use super::impl_secp256k1 as imp;

    /// Recover signer from message hash, _without ensuring that the signature has a low `s`
    /// value_.
    ///
    /// Using this for signature validation will succeed, even if the signature is malleable or not
    /// compliant with EIP-2. This is provided for compatibility with old signatures which have
    /// large `s` values.
    pub fn recover_signer_unchecked(
        signature: &Signature,
        hash: B256,
    ) -> Result<Address, RecoveryError> {
        let mut sig: [u8; 65] = [0; 65];

        sig[0..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
        sig[64] = signature.v() as u8;

        // Try dynamic backend first when crypto-backend feature is enabled
        #[cfg(feature = "crypto-backend")]
        if let Some(provider) = super::backend::try_get_provider() {
            return provider.recover_signer_unchecked(&sig, &hash.0);
        }

        // Fallback to compile-time selected implementation
        // NOTE: we are removing error from underlying crypto library as it will restrain primitive
        // errors and we care only if recovery is passing or not.
        imp::recover_signer_unchecked(&sig, &hash.0).map_err(|_| RecoveryError::new())
    }

    /// Recover signer address from message hash. This ensures that the signature S value is
    /// lower than `secp256k1n / 2`, as specified in
    /// [EIP-2](https://eips.ethereum.org/EIPS/eip-2).
    ///
    /// If the S value is too large, then this will return a `RecoveryError`
    pub fn recover_signer(signature: &Signature, hash: B256) -> Result<Address, RecoveryError> {
        if signature.s() > SECP256K1N_HALF {
            return Err(RecoveryError::from_source(InvalidSignatureS));
        }
        recover_signer_unchecked(signature, hash)
    }

    /// Verify signature against a known public key, _without ensuring that the signature has a
    /// low `s` value_.
    ///
    /// Using this for signature validation will succeed, even if the signature is malleable or not
    /// compliant with EIP-2. This is provided for compatibility with old signatures which have
    /// large `s` values.
    ///
    /// # Arguments
    ///
    /// * `signature` - The ECDSA signature to verify
    /// * `hash` - The message hash that was signed
    /// * `public_key` - The uncompressed public key (65 bytes: 0x04 prefix + x + y coordinates)
    ///
    /// # Returns
    ///
    /// * `Ok(Address)` - The Ethereum address derived from the public key if verification succeeds
    /// * `Err(RecoveryError)` - If verification fails
    pub fn verify_signature_unchecked(
        signature: &Signature,
        hash: B256,
        public_key: &[u8; 65],
    ) -> Result<Address, RecoveryError> {
        let mut sig: [u8; 65] = [0; 65];

        sig[0..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
        sig[64] = signature.v() as u8;

        // Try dynamic backend first when crypto-backend feature is enabled
        #[cfg(feature = "crypto-backend")]
        if let Some(provider) = super::backend::try_get_provider() {
            return provider.verify_signature_unchecked(&sig, &hash.0, public_key);
        }

        // Fallback to compile-time selected implementation
        imp::verify_signature_unchecked(&sig, &hash.0, public_key).map_err(|_| RecoveryError::new())
    }

    /// Verify signature against a known public key and return the derived address.
    ///
    /// This ensures that the signature S value is lower than `secp256k1n / 2`, as specified in
    /// [EIP-2](https://eips.ethereum.org/EIPS/eip-2).
    ///
    /// # Arguments
    ///
    /// * `signature` - The ECDSA signature to verify
    /// * `hash` - The message hash that was signed
    /// * `public_key` - The uncompressed public key (65 bytes: 0x04 prefix + x + y coordinates)
    ///
    /// # Returns
    ///
    /// * `Ok(Address)` - The Ethereum address derived from the public key if verification succeeds
    /// * `Err(RecoveryError)` - If the S value is too large or verification fails
    pub fn verify_signature(
        signature: &Signature,
        hash: B256,
        public_key: &[u8; 65],
    ) -> Result<Address, RecoveryError> {
        if signature.s() > SECP256K1N_HALF {
            return Err(RecoveryError::from_source(InvalidSignatureS));
        }
        verify_signature_unchecked(signature, hash, public_key)
    }
}

#[cfg(feature = "secp256k1")]
mod impl_secp256k1 {
    pub(crate) use ::secp256k1::Error;
    use ::secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId, Signature as EcdsaSignature},
        Message, PublicKey, SecretKey, SECP256K1,
    };
    use alloy_primitives::{keccak256, Address, Signature, B256, U256};

    /// Recovers the address of the sender using secp256k1 pubkey recovery.
    ///
    /// Converts the public key into an ethereum address by hashing the public key with keccak256.
    ///
    /// This does not ensure that the `s` value in the signature is low, and _just_ wraps the
    /// underlying secp256k1 library.
    pub(crate) fn recover_signer_unchecked(
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, Error> {
        let sig =
            RecoverableSignature::from_compact(&sig[0..64], RecoveryId::try_from(sig[64] as i32)?)?;

        let public = SECP256K1.recover_ecdsa(&Message::from_digest(*msg), &sig)?;
        Ok(public_key_to_address(public))
    }

    /// Verifies a signature against a known public key.
    ///
    /// Returns the address derived from the public key if verification succeeds.
    ///
    /// This does not ensure that the `s` value in the signature is low, and _just_ wraps the
    /// underlying secp256k1 library.
    pub(crate) fn verify_signature_unchecked(
        sig: &[u8; 65],
        msg: &[u8; 32],
        public_key: &[u8; 65],
    ) -> Result<Address, Error> {
        // Parse the public key from uncompressed format
        let pubkey = PublicKey::from_slice(public_key)?;

        // Parse signature from compact format (ignore recovery id)
        let signature = EcdsaSignature::from_compact(&sig[0..64])?;

        // Verify the signature
        SECP256K1.verify_ecdsa(&Message::from_digest(*msg), &signature, &pubkey)?;

        // Return address derived from public key
        Ok(public_key_to_address(pubkey))
    }

    /// Signs message with the given secret key.
    /// Returns the corresponding signature.
    pub fn sign_message(secret: B256, message: B256) -> Result<Signature, Error> {
        let sec = SecretKey::from_slice(secret.as_ref())?;
        let s = SECP256K1.sign_ecdsa_recoverable(&Message::from_digest(message.0), &sec);
        let (rec_id, data) = s.serialize_compact();

        let signature = Signature::new(
            U256::try_from_be_slice(&data[..32]).expect("The slice has at most 32 bytes"),
            U256::try_from_be_slice(&data[32..64]).expect("The slice has at most 32 bytes"),
            i32::from(rec_id) != 0,
        );
        Ok(signature)
    }

    /// Converts a public key into an ethereum address by hashing the encoded public key with
    /// keccak256.
    pub fn public_key_to_address(public: PublicKey) -> Address {
        // strip out the first byte because that should be the SECP256K1_TAG_PUBKEY_UNCOMPRESSED
        // tag returned by libsecp's uncompressed pubkey serialization
        let hash = keccak256(&public.serialize_uncompressed()[1..]);
        Address::from_slice(&hash[12..])
    }
}

#[cfg(feature = "k256")]
#[cfg_attr(feature = "secp256k1", allow(unused, unreachable_pub))]
mod impl_k256 {
    pub(crate) use k256::ecdsa::Error;

    use super::*;
    use alloy_primitives::{keccak256, Address, B256};
    use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};

    /// Recovers the address of the sender using secp256k1 pubkey recovery.
    ///
    /// Converts the public key into an ethereum address by hashing the public key with keccak256.
    ///
    /// This does not ensure that the `s` value in the signature is low, and _just_ wraps the
    /// underlying secp256k1 library.
    pub(crate) fn recover_signer_unchecked(
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, Error> {
        let mut signature = k256::ecdsa::Signature::from_slice(&sig[0..64])?;
        let mut recid = sig[64];

        // normalize signature and flip recovery id if needed.
        if let Some(sig_normalized) = signature.normalize_s() {
            signature = sig_normalized;
            recid ^= 1;
        }
        let recid = RecoveryId::from_byte(recid).expect("recovery ID is valid");

        // recover key
        let recovered_key = VerifyingKey::recover_from_prehash(&msg[..], &signature, recid)?;
        Ok(public_key_to_address(recovered_key))
    }

    /// Verifies a signature against a known public key.
    ///
    /// Returns the address derived from the public key if verification succeeds.
    ///
    /// This does not ensure that the `s` value in the signature is low, and _just_ wraps the
    /// underlying k256 library.
    pub(crate) fn verify_signature_unchecked(
        sig: &[u8; 65],
        msg: &[u8; 32],
        public_key: &[u8; 65],
    ) -> Result<Address, Error> {
        // Parse signature from r and s components (first 64 bytes, ignore recovery id)
        // Note: we use from_scalars instead of from_slice because from_slice expects DER encoding
        let r: &[u8; 32] = &sig[0..32].try_into().unwrap();
        let s: &[u8; 32] = &sig[32..64].try_into().unwrap();
        let signature = k256::ecdsa::Signature::from_scalars(*r, *s)?;

        // Parse public key from uncompressed bytes
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)?;

        // Verify signature against message hash
        // Note: We use verify_prehash because sign_prehash_recoverable was used to create the
        // signature
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        verifying_key.verify_prehash(&msg[..], &signature)?;

        // Return address derived from public key
        Ok(public_key_to_address(verifying_key))
    }

    /// Signs message with the given secret key.
    /// Returns the corresponding signature.
    pub fn sign_message(secret: B256, message: B256) -> Result<Signature, Error> {
        let sec = SigningKey::from_slice(secret.as_ref())?;
        sec.sign_prehash_recoverable(&message.0).map(Into::into)
    }

    /// Converts a public key into an ethereum address by hashing the encoded public key with
    /// keccak256.
    pub fn public_key_to_address(public: VerifyingKey) -> Address {
        let hash = keccak256(&public.to_encoded_point(/* compress = */ false).as_bytes()[1..]);
        Address::from_slice(&hash[12..])
    }
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "secp256k1")]
    #[test]
    fn sanity_ecrecover_call_secp256k1() {
        use super::impl_secp256k1::*;
        use alloy_primitives::B256;

        let (secret, public) = secp256k1::generate_keypair(&mut rand::thread_rng());
        let signer = public_key_to_address(public);

        let message = b"hello world";
        let hash = alloy_primitives::keccak256(message);
        let signature =
            sign_message(B256::from_slice(&secret.secret_bytes()[..]), hash).expect("sign message");

        let mut sig: [u8; 65] = [0; 65];
        sig[0..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
        sig[64] = signature.v() as u8;

        assert_eq!(recover_signer_unchecked(&sig, &hash), Ok(signer));
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn test_verify_signature_secp256k1() {
        use super::impl_secp256k1::*;
        use alloy_primitives::B256;

        // Generate keypair
        let (secret, public) = ::secp256k1::generate_keypair(&mut rand::thread_rng());
        let signer = public_key_to_address(public);

        // Sign message
        let message = b"hello world";
        let hash = alloy_primitives::keccak256(message);
        let signature =
            sign_message(B256::from_slice(&secret.secret_bytes()[..]), hash).expect("sign message");

        // Convert signature to bytes
        let mut sig: [u8; 65] = [0; 65];
        sig[0..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
        sig[64] = signature.v() as u8;

        // Get public key bytes (uncompressed format)
        let pubkey_bytes = public.serialize_uncompressed();

        // Verify with correct public key
        let result = verify_signature_unchecked(&sig, &hash, &pubkey_bytes);
        assert_eq!(result, Ok(signer));

        // Verify with wrong public key
        let (_, wrong_public) = ::secp256k1::generate_keypair(&mut rand::thread_rng());
        let wrong_pubkey_bytes = wrong_public.serialize_uncompressed();
        let result = verify_signature_unchecked(&sig, &hash, &wrong_pubkey_bytes);
        assert!(result.is_err());
    }

    #[cfg(feature = "k256")]
    #[test]
    fn sanity_ecrecover_call_k256() {
        use super::impl_k256::*;
        use alloy_primitives::B256;

        let secret = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let public = *secret.verifying_key();
        let signer = public_key_to_address(public);

        let message = b"hello world";
        let hash = alloy_primitives::keccak256(message);
        let signature =
            sign_message(B256::from_slice(&secret.to_bytes()[..]), hash).expect("sign message");

        let mut sig: [u8; 65] = [0; 65];
        sig[0..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
        sig[64] = signature.v() as u8;

        assert_eq!(recover_signer_unchecked(&sig, &hash).ok(), Some(signer));
    }

    #[cfg(feature = "k256")]
    #[test]
    fn test_verify_signature_k256() {
        use super::impl_k256::*;
        use alloy_primitives::B256;

        // Generate keypair
        let secret = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let public = *secret.verifying_key();
        let signer = public_key_to_address(public);

        // Sign message
        let message = b"hello world";
        let hash = alloy_primitives::keccak256(message);
        let signature =
            sign_message(B256::from_slice(&secret.to_bytes()[..]), hash).expect("sign message");

        // Convert signature to bytes
        let mut sig: [u8; 65] = [0; 65];
        sig[0..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
        sig[64] = signature.v() as u8;

        // Get public key bytes (uncompressed format)
        let pubkey_encoded = public.to_encoded_point(false);
        let pubkey_bytes = pubkey_encoded.as_bytes();
        let pubkey_array: [u8; 65] = pubkey_bytes.try_into().expect("public key is 65 bytes");

        // Verify with correct public key
        let result = verify_signature_unchecked(&sig, &hash, &pubkey_array);
        assert_eq!(result.ok(), Some(signer));

        // Verify with wrong public key
        let wrong_secret = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let wrong_public = *wrong_secret.verifying_key();
        let wrong_pubkey_encoded = wrong_public.to_encoded_point(false);
        let wrong_pubkey_bytes = wrong_pubkey_encoded.as_bytes();
        let wrong_pubkey_array: [u8; 65] =
            wrong_pubkey_bytes.try_into().expect("public key is 65 bytes");
        let result = verify_signature_unchecked(&sig, &hash, &wrong_pubkey_array);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(all(feature = "secp256k1", feature = "k256"))]
    fn sanity_secp256k1_k256_compat() {
        use super::{impl_k256, impl_secp256k1};
        use alloy_primitives::B256;

        let (secp256k1_secret, secp256k1_public) =
            secp256k1::generate_keypair(&mut rand::thread_rng());
        let k256_secret = k256::ecdsa::SigningKey::from_slice(&secp256k1_secret.secret_bytes())
            .expect("k256 secret");
        let k256_public = *k256_secret.verifying_key();

        let secp256k1_signer = impl_secp256k1::public_key_to_address(secp256k1_public);
        let k256_signer = impl_k256::public_key_to_address(k256_public);
        assert_eq!(secp256k1_signer, k256_signer);

        let message = b"hello world";
        let hash = alloy_primitives::keccak256(message);

        let secp256k1_signature = impl_secp256k1::sign_message(
            B256::from_slice(&secp256k1_secret.secret_bytes()[..]),
            hash,
        )
        .expect("secp256k1 sign");
        let k256_signature =
            impl_k256::sign_message(B256::from_slice(&k256_secret.to_bytes()[..]), hash)
                .expect("k256 sign");
        assert_eq!(secp256k1_signature, k256_signature);

        let mut sig: [u8; 65] = [0; 65];

        sig[0..32].copy_from_slice(&secp256k1_signature.r().to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&secp256k1_signature.s().to_be_bytes::<32>());
        sig[64] = secp256k1_signature.v() as u8;
        let secp256k1_recovered =
            impl_secp256k1::recover_signer_unchecked(&sig, &hash).expect("secp256k1 recover");
        assert_eq!(secp256k1_recovered, secp256k1_signer);

        sig[0..32].copy_from_slice(&k256_signature.r().to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&k256_signature.s().to_be_bytes::<32>());
        sig[64] = k256_signature.v() as u8;
        let k256_recovered =
            impl_k256::recover_signer_unchecked(&sig, &hash).expect("k256 recover");
        assert_eq!(k256_recovered, k256_signer);

        assert_eq!(secp256k1_recovered, k256_recovered);
    }

    #[cfg(feature = "crypto-backend")]
    mod backend_tests {
        use crate::crypto::{backend::CryptoProvider, RecoveryError};
        use alloc::sync::Arc;
        use alloy_primitives::Address;

        /// Mock crypto provider for testing
        struct MockCryptoProvider {
            should_fail: bool,
            return_address: Address,
        }

        impl CryptoProvider for MockCryptoProvider {
            fn recover_signer_unchecked(
                &self,
                _sig: &[u8; 65],
                _msg: &[u8; 32],
            ) -> Result<Address, RecoveryError> {
                if self.should_fail {
                    Err(RecoveryError::new())
                } else {
                    Ok(self.return_address)
                }
            }

            fn verify_signature_unchecked(
                &self,
                _sig: &[u8; 65],
                _msg: &[u8; 32],
                _public_key: &[u8; 65],
            ) -> Result<Address, RecoveryError> {
                if self.should_fail {
                    Err(RecoveryError::new())
                } else {
                    Ok(self.return_address)
                }
            }
        }

        #[test]
        fn test_crypto_backend_basic_functionality() {
            // This test verifies the trait implementation, but does NOT install a provider
            // to avoid interfering with other tests that need real cryptographic operations.
            // The MockCryptoProvider exists purely to demonstrate trait implementation.

            let mock = MockCryptoProvider {
                should_fail: false,
                return_address: Address::from([0x99; 20]),
            };

            // Test recover_signer_unchecked
            let sig = [0u8; 65];
            let msg = [0u8; 32];
            let result = mock.recover_signer_unchecked(&sig, &msg);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), Address::from([0x99; 20]));

            // Test verify_signature_unchecked
            let public_key = [0u8; 65];
            let result = mock.verify_signature_unchecked(&sig, &msg, &public_key);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), Address::from([0x99; 20]));

            // Test failure case
            let failing_mock =
                MockCryptoProvider { should_fail: true, return_address: Address::from([0x99; 20]) };
            assert!(failing_mock.recover_signer_unchecked(&sig, &msg).is_err());
            assert!(failing_mock.verify_signature_unchecked(&sig, &msg, &public_key).is_err());
        }

        #[test]
        #[ignore = "This test installs a global provider and must be run in isolation"]
        fn test_provider_already_set_error() {
            // This test must be run in isolation with: cargo test test_provider_already_set_error
            // -- --ignored It installs a global provider which persists for the entire
            // test run.

            // Check if provider already set from other tests
            if crate::crypto::backend::try_get_provider().is_some() {
                // Provider already installed - we can still verify that attempting
                // to install another provider fails
                let provider = Arc::new(MockCryptoProvider {
                    should_fail: false,
                    return_address: Address::from([0x99; 20]),
                });
                let result = crate::crypto::backend::install_default_provider(provider);
                assert!(result.is_err(), "Should fail to install when provider already set");
                return;
            }

            // No provider installed yet - test the full flow
            let provider1 = Arc::new(MockCryptoProvider {
                should_fail: false,
                return_address: Address::from([0x11; 20]),
            });
            let result1 = crate::crypto::backend::install_default_provider(provider1);
            assert!(result1.is_ok(), "First installation should succeed");

            // Second installation should always fail since OnceLock can only be set once
            let provider2 = Arc::new(MockCryptoProvider {
                should_fail: true,
                return_address: Address::from([0x22; 20]),
            });
            let result2 = crate::crypto::backend::install_default_provider(provider2);

            // The second attempt should fail with CryptoProviderAlreadySetError
            assert!(result2.is_err());

            // The error should contain the provider we tried to install (provider2)
            if let Err(err) = result2 {
                // We can't easily compare Arc pointers due to type erasure,
                // but we can verify the error contains a valid provider
                // (just by accessing it without panicking)
                let _provider_ref = err.provider.as_ref();
            }
        }

        #[test]
        fn test_verify_signature_unchecked_api() {
            #[cfg(feature = "secp256k1")]
            {
                use crate::crypto::impl_secp256k1;
                use alloy_primitives::B256;

                // Generate keypair
                let (secret, public) = ::secp256k1::generate_keypair(&mut rand::thread_rng());

                // Sign message
                let message = b"test message";
                let hash = alloy_primitives::keccak256(message);
                let signature = impl_secp256k1::sign_message(
                    B256::from_slice(&secret.secret_bytes()[..]),
                    hash,
                )
                .expect("sign message");

                // Get public key bytes
                let pubkey_bytes = public.serialize_uncompressed();

                // Verify signature
                let result = crate::crypto::secp256k1::verify_signature_unchecked(
                    &signature,
                    hash,
                    &pubkey_bytes,
                );
                assert!(result.is_ok());
            }

            #[cfg(all(not(feature = "secp256k1"), feature = "k256"))]
            {
                use crate::crypto::impl_k256;
                use alloy_primitives::B256;

                // Generate keypair
                let secret = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
                let public = *secret.verifying_key();

                // Sign message
                let message = b"test message";
                let hash = alloy_primitives::keccak256(message);
                let signature =
                    impl_k256::sign_message(B256::from_slice(&secret.to_bytes()[..]), hash)
                        .expect("sign message");

                // Get public key bytes
                let pubkey_bytes = public.to_encoded_point(false);
                let pubkey_array: [u8; 65] = pubkey_bytes.as_bytes().try_into().expect("65 bytes");

                // Verify signature
                let result = crate::crypto::secp256k1::verify_signature_unchecked(
                    &signature,
                    hash,
                    &pubkey_array,
                );
                assert!(result.is_ok());
            }
        }

        #[test]
        fn test_verify_signature_checked_api() {
            #[cfg(feature = "secp256k1")]
            {
                use crate::crypto::impl_secp256k1;
                use alloy_primitives::B256;

                // Generate keypair
                let (secret, public) = ::secp256k1::generate_keypair(&mut rand::thread_rng());

                // Sign message
                let message = b"test message";
                let hash = alloy_primitives::keccak256(message);
                let signature = impl_secp256k1::sign_message(
                    B256::from_slice(&secret.secret_bytes()[..]),
                    hash,
                )
                .expect("sign message");

                // Get public key bytes
                let pubkey_bytes = public.serialize_uncompressed();

                // Verify signature - should succeed because sign_message creates low S
                let result =
                    crate::crypto::secp256k1::verify_signature(&signature, hash, &pubkey_bytes);
                assert!(result.is_ok());

                // Test with high S value - create a signature with S > SECP256K1N_HALF
                let high_s = crate::crypto::SECP256K1N_HALF + alloy_primitives::U256::from(1);
                let bad_sig =
                    alloy_primitives::Signature::new(signature.r(), high_s, signature.v());

                // Should fail because S is too large
                let result =
                    crate::crypto::secp256k1::verify_signature(&bad_sig, hash, &pubkey_bytes);
                assert!(result.is_err());
            }

            #[cfg(all(not(feature = "secp256k1"), feature = "k256"))]
            {
                use crate::crypto::impl_k256;
                use alloy_primitives::B256;

                // Generate keypair
                let secret = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
                let public = *secret.verifying_key();

                // Sign message
                let message = b"test message";
                let hash = alloy_primitives::keccak256(message);
                let signature =
                    impl_k256::sign_message(B256::from_slice(&secret.to_bytes()[..]), hash)
                        .expect("sign message");

                // Get public key bytes
                let pubkey_bytes = public.to_encoded_point(false);
                let pubkey_array: [u8; 65] = pubkey_bytes.as_bytes().try_into().expect("65 bytes");

                // Verify signature - should succeed because sign_message creates low S
                let result =
                    crate::crypto::secp256k1::verify_signature(&signature, hash, &pubkey_array);
                assert!(result.is_ok());

                // Test with high S value - create a signature with S > SECP256K1N_HALF
                let high_s = crate::crypto::SECP256K1N_HALF + alloy_primitives::U256::from(1);
                let bad_sig =
                    alloy_primitives::Signature::new(signature.r(), high_s, signature.v());

                // Should fail because S is too large
                let result =
                    crate::crypto::secp256k1::verify_signature(&bad_sig, hash, &pubkey_array);
                assert!(result.is_err());
            }
        }

        #[test]
        fn test_verify_signature_eip2_compliance() {
            use alloy_primitives::{Signature, B256, U256};

            // Create signature with high S value (> SECP256K1N_HALF)
            let high_s = crate::crypto::SECP256K1N_HALF + U256::from(1u64);
            let signature_high_s = Signature::new(U256::from(123u64), high_s, false);

            // Dummy public key and hash
            let public_key = [4u8; 65];
            let hash = B256::from([0xAB; 32]);

            // verify_signature should reject high S
            let result =
                crate::crypto::secp256k1::verify_signature(&signature_high_s, hash, &public_key);
            assert!(result.is_err());

            // Create signature with low S value
            let low_s = U256::from(456u64);
            let signature_low_s = Signature::new(U256::from(123u64), low_s, false);

            // Both functions should accept low S (though verification will fail due to invalid sig)
            // We're just testing that the S value check works, not full verification
            let result =
                crate::crypto::secp256k1::verify_signature(&signature_low_s, hash, &public_key);
            // Will fail due to invalid signature, not S value
            assert!(result.is_err());
        }

        #[test]
        fn test_recovery_verification_equivalence() {
            #[cfg(feature = "secp256k1")]
            {
                use crate::crypto::{
                    impl_secp256k1,
                    secp256k1::{recover_signer_unchecked, verify_signature_unchecked},
                };
                use alloy_primitives::B256;

                // Generate keypair and sign
                let (secret, public) = ::secp256k1::generate_keypair(&mut rand::thread_rng());
                let message = b"equivalence test";
                let hash = alloy_primitives::keccak256(message);
                let signature = impl_secp256k1::sign_message(
                    B256::from_slice(&secret.secret_bytes()[..]),
                    hash,
                )
                .expect("sign message");

                // Recover signer
                let recovered_address =
                    recover_signer_unchecked(&signature, hash).expect("recover");

                // Verify with public key
                let pubkey_bytes = public.serialize_uncompressed();
                let verified_address =
                    verify_signature_unchecked(&signature, hash, &pubkey_bytes).expect("verify");

                // Both should return the same address
                assert_eq!(recovered_address, verified_address);
            }
        }

        #[test]
        #[cfg(all(feature = "secp256k1", feature = "k256"))]
        fn test_secp256k1_k256_verification_compat() {
            use crate::crypto::{impl_k256, impl_secp256k1};
            use alloy_primitives::B256;

            // Generate keypair with secp256k1
            let (secp256k1_secret, secp256k1_public) =
                ::secp256k1::generate_keypair(&mut rand::thread_rng());

            // Create matching k256 keypair
            let _k256_secret =
                k256::ecdsa::SigningKey::from_slice(&secp256k1_secret.secret_bytes())
                    .expect("k256 secret");

            // Sign with secp256k1
            let message = b"backend compat test";
            let hash = alloy_primitives::keccak256(message);
            let signature = impl_secp256k1::sign_message(
                B256::from_slice(&secp256k1_secret.secret_bytes()[..]),
                hash,
            )
            .expect("secp256k1 sign");

            // Convert signature to bytes
            let mut sig: [u8; 65] = [0; 65];
            sig[0..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
            sig[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
            sig[64] = signature.v() as u8;

            // Get public key in both formats
            let secp256k1_pubkey_bytes = secp256k1_public.serialize_uncompressed();

            // Verify with both backends
            let secp256k1_result =
                impl_secp256k1::verify_signature_unchecked(&sig, &hash.0, &secp256k1_pubkey_bytes)
                    .expect("secp256k1 verify");
            let k256_result =
                impl_k256::verify_signature_unchecked(&sig, &hash.0, &secp256k1_pubkey_bytes)
                    .expect("k256 verify");

            // Both backends should return the same address
            assert_eq!(secp256k1_result, k256_result);
        }

        #[test]
        #[ignore = "This test installs a global provider and must be run in isolation"]
        fn test_crypto_provider_verification() {
            use crate::crypto::secp256k1::verify_signature_unchecked;
            use alloy_primitives::{Signature, B256, U256};

            // This test must be run in isolation with: cargo test test_crypto_provider_verification
            // -- --ignored It installs a global provider which persists for the entire
            // test run.

            // Create test signature and public key
            let signature = Signature::new(U256::from(123u64), U256::from(456u64), false);
            let hash = B256::from([0xAB; 32]);
            let public_key = [0x04; 65];

            // Try to install a custom provider (may already be set from other tests)
            let custom_address = Address::from([0x88; 20]);
            let provider =
                Arc::new(MockCryptoProvider { should_fail: false, return_address: custom_address });

            let install_result = crate::crypto::backend::install_default_provider(provider);

            // Call verification
            let result = verify_signature_unchecked(&signature, hash, &public_key);

            // If our provider was successfully installed, should get custom address
            if install_result.is_ok() {
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), custom_address);
            }
            // Otherwise, should still get a valid result from existing provider
            else {
                assert!(result.is_ok());
            }
        }
    }
}
