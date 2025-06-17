use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, ristretto::CompressedRistretto};
use sha3::{Digest, Sha3_512}; // For hashing if needed within types, though mostly for challenge

// Minimal struct definitions based on Tari's types, for RevealedValue check.

// Placeholder for TariScript - only its byte representation matters for hashing.
#[derive(Debug, Clone, Default)]
pub struct TariScript(pub Vec<u8>); // Assuming it can be represented or hashed as bytes

impl TariScript {
    pub fn new(data: Vec<u8>) -> Self { Self(data) }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

// Enum for RangeProofType
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeProofType {
    BulletProofPlus = 0,
    RevealedValue = 1,
}

impl Default for RangeProofType {
    fn default() -> Self { RangeProofType::BulletProofPlus }
}

impl RangeProofType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(RangeProofType::BulletProofPlus),
            1 => Some(RangeProofType::RevealedValue),
            _ => None,
        }
    }
}

// Enum for OutputType (matches common usage, simplified)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum OutputType {
    #[default]
    Standard = 0,
    Coinbase = 1,
    Burn = 2,
    ValidatorNodeRegistration = 3,
    CodeTemplateRegistration = 4,
}

impl OutputType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Standard,
            1 => Self::Coinbase,
            2 => Self::Burn,
            3 => Self::ValidatorNodeRegistration,
            4 => Self::CodeTemplateRegistration,
            _ => Self::Standard, // Default or error
        }
    }
}


// Placeholder for OutputFeatures
#[derive(Debug, Clone, Default)]
pub struct OutputFeatures {
    pub output_type: OutputType,
    pub maturity: u64,
    // pub sidechain_features: Option<Vec<u8>>, // Simplified
    pub range_proof_type: RangeProofType,
    // pub validator_node_registration: Option<Vec<u8>>, // Simplified
}

impl OutputFeatures {
    // This needs to match Tari's consensus serialization for hashing in metadata signature
    pub fn to_consensus_bytes_for_hashing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.output_type as u8);
        bytes.extend_from_slice(&self.maturity.to_le_bytes());
        // In real Tari, sidechain_features and validator_node_registration would be serialized here too if present.
        // For now, this is a simplification.
        // The range_proof_type itself is NOT part of the OutputFeatures struct that gets hashed
        // for the metadata signature message in Tari's reference code.
        // See `TransactionOutput::metadata_signature_message_from_parts`.
        // It hashes `features` (which doesn't include range_proof_type for this specific hash).
        bytes
    }
}


// Placeholder for Covenant - only its byte representation matters for hashing.
#[derive(Debug, Clone, Default)]
pub struct Covenant(pub Vec<u8>);

impl Covenant {
    pub fn new(data: Vec<u8>) -> Self { Self(data) }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

// Placeholder for EncryptedData - only its byte representation matters for hashing.
#[derive(Debug, Clone, Default)]
pub struct EncryptedData(pub Vec<u8>);

impl EncryptedData {
    pub fn new(data: Vec<u8>) -> Self { Self(data) }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

// CompressedPublicKey (wrapper around RistrettoPoint's compressed form)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompressedPublicKey(pub CompressedRistretto);

impl CompressedPublicKey {
    pub fn from_point(point: &RistrettoPoint) -> Self {
        Self(point.compress())
    }
    pub fn as_compressed_ristretto(&self) -> &CompressedRistretto {
        &self.0
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

// ComAndPubSignature structure
// Fields based on assumption: gRPC ComSignature { commitment (-> R_c), public_nonce (-> R_k), signature_u (-> u_a), signature_v (-> u_x) }
#[derive(Debug, Clone, Default)]
pub struct ComAndPubSignature {
    // These are kept as compressed points as they are used as such in challenge
    ephemeral_commitment_bytes: CompressedRistretto, // R_c (commitment to blinding factor for ephemeral key)
    ephemeral_pubkey_bytes: CompressedRistretto,     // R_k (ephemeral public key)
    u_a: Scalar, // s_a in Tari (signature component for amount)
    u_x: Scalar, // s_x in Tari (signature component for blinding factor) - not used in u_a check directly
}

impl ComAndPubSignature {
    // Creates from raw byte components typically received from gRPC or similar sources.
    // Assumes `commitment_bytes` and `public_nonce_bytes` are 32-byte compressed Ristretto points.
    // Assumes `u_a_bytes` and `u_x_bytes` are 32-byte scalar representations.
    pub fn from_rpc_bytes(
        commitment_bytes_slice: &[u8],    // maps to rpc ComSignature.commitment
        public_nonce_bytes_slice: &[u8], // maps to rpc ComSignature.public_nonce
        u_a_bytes_slice: &[u8],          // maps to rpc ComSignature.signature_u
        u_x_bytes_slice: &[u8],          // maps to rpc ComSignature.signature_v
    ) -> Result<Self, String> {
        if commitment_bytes_slice.len() != 32 || public_nonce_bytes_slice.len() != 32 ||
           u_a_bytes_slice.len() != 32 || u_x_bytes_slice.len() != 32 {
            return Err("Invalid byte length for ComAndPubSignature components".to_string());
        }

        let mut commitment_arr = [0u8; 32];
        commitment_arr.copy_from_slice(commitment_bytes_slice);
        let ephemeral_commitment_bytes = CompressedRistretto(commitment_arr);

        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(public_nonce_bytes_slice);
        let ephemeral_pubkey_bytes = CompressedRistretto(pubkey_arr);

        let mut u_a_arr = [0u8; 32];
        u_a_arr.copy_from_slice(u_a_bytes_slice);
        let u_a = Scalar::from_bytes_mod_order(u_a_arr);

        let mut u_x_arr = [0u8; 32];
        u_x_arr.copy_from_slice(u_x_bytes_slice);
        let u_x = Scalar::from_bytes_mod_order(u_x_arr);

        Ok(Self {
            ephemeral_commitment_bytes,
            ephemeral_pubkey_bytes,
            u_a,
            u_x,
        })
    }

    // Constructor for testing or direct use if components are already processed
    pub fn new(
        ephemeral_commitment: CompressedRistretto,
        ephemeral_pubkey: CompressedRistretto,
        u_a: Scalar,
        u_x: Scalar,
    ) -> Self {
        Self {
            ephemeral_commitment_bytes: ephemeral_commitment,
            ephemeral_pubkey_bytes: ephemeral_pubkey,
            u_a,
            u_x,
        }
    }


    pub fn ephemeral_commitment(&self) -> &CompressedRistretto {
        &self.ephemeral_commitment_bytes
    }

    pub fn ephemeral_pubkey(&self) -> &CompressedRistretto {
        &self.ephemeral_pubkey_bytes
    }

    pub fn u_a(&self) -> &Scalar {
        &self.u_a
    }

    // pub fn u_x(&self) -> &Scalar { &self.u_x } // Not used in this subtask
}

// TransactionOutputVersion
// Tari gRPC uses u32 for version, but consensus hashing uses u8.
#[derive(Debug, Clone, Copy)]
pub struct TransactionOutputVersion(pub u8);

impl Default for TransactionOutputVersion {
    fn default() -> Self {
        TransactionOutputVersion(1) // Default to a common version
    }
}

impl TransactionOutputVersion {
    pub fn from_u32(value: u32) -> Result<Self, String> {
        if value > u8::MAX as u32 {
            Err(format!("Version {} is too large for u8", value))
        } else {
            Ok(TransactionOutputVersion(value as u8))
        }
    }
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

// Helper to convert various types to their byte representations for hashing.
// This is a simplification; Tari uses specific serialization for consensus hashing.

pub trait CanonicalBytes {
    fn to_canonical_bytes(&self) -> Vec<u8>;
}

impl CanonicalBytes for TariScript {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}
impl CanonicalBytes for OutputFeatures {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_consensus_bytes_for_hashing()
    }
}
impl CanonicalBytes for Covenant {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}
impl CanonicalBytes for EncryptedData {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}
impl CanonicalBytes for CompressedPublicKey {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().tovec()
    }
}
impl CanonicalBytes for CompressedRistretto {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        self.as_bytes().tovec()
    }
}
impl CanonicalBytes for u64 {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}
impl CanonicalBytes for TransactionOutputVersion {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        vec![self.0]
    }
}
