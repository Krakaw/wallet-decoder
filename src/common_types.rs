#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment(pub [u8; 32]);
