pub mod range_proof;

use super::range_proof::RangeProof;
use serde::{Deserialize, Serialize};
use tari_common_types::types::CompressedCommitment;

/// Represents an Unspent Transaction Output (UTXO).
///
/// UTXOs are the fundamental building blocks of transactions in many cryptocurrencies.
/// Each UTXO represents a specific amount of cryptocurrency that has been received
/// by a wallet and has not yet been spent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Utxo {
    /// The unique hash identifying this output.
    /// This is often the hash of the transaction that created the output, combined with an output index.
    pub output_hash: String,
    /// The value (amount) of cryptocurrency held by this UTXO, typically in the smallest unit (e.g., microTari).
    pub value: u64,
    /// The block height at which this UTXO was confirmed on the blockchain.
    /// This can be used to determine the age of the UTXO and for confirmation checks.
    pub block_height: u64,
    /// The script public key (scriptPubKey) that locks this UTXO.
    /// Spending this UTXO requires satisfying the conditions of this script,
    /// usually by providing a valid signature corresponding to the public key.
    pub script_pubkey: String,
    /// The type of output, indicating how it was created or its specific characteristics.
    pub output_type: OutputType,
    /// The range proof for the UTXO.
    pub proof: Option<RangeProof>,
    /// The homomorphic commitment to the value of the UTXO.
    pub commitment: CompressedCommitment,
}

/// Represents detailed information about a transaction.
///
/// This struct is typically used to hold data retrieved from a blockchain explorer or node,
/// providing a comprehensive view of a specific transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionDetails {
    /// The unique identifier (hash) of the transaction.
    pub tx_id: String,
    /// A list of UTXOs that are consumed as inputs by this transaction.
    pub inputs: Vec<Utxo>,
    /// A list of UTXOs that are created as outputs by this transaction.
    pub outputs: Vec<Utxo>,
    /// The timestamp of the transaction, usually indicating when it was mined or first seen.
    /// The format can vary (e.g., Unix timestamp).
    pub timestamp: u64,
}

/// Enumerates the different types of transaction outputs.
///
/// The output type can influence how a UTXO is handled or interpreted by the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OutputType {
    /// A standard transaction output. This is the most common type.
    Standard,
    /// A coinbase output. This type of output is created by miners as a reward for mining a new block.
    /// Coinbase UTXOs often have special rules, such as a maturity period before they can be spent.
    Coinbase,
    // Potentially other types like `Stealth` for privacy-enhanced outputs,
    // or `Timelocked` for outputs that can only be spent after a certain time.
    // Add other output types as needed by the specific blockchain protocol.
    Burn,
    ValidatorNodeRegistration,
    CodeTemplateRegistration,
}
