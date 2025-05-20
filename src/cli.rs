use clap::Parser;
use tari_utilities::SafePassword;

#[derive(Parser, Debug)]
#[clap(author, version, about = "Tari Wallet Tools")]
pub struct Args {
    /// Command to execute (generate-wallet or decode-address)
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Generate a new Tari wallet
    GenerateWallet {
        /// Optional password for the wallet
        #[clap(long)]
        password: Option<SafePassword>,

        /// Network to use (default: mainnet)
        #[clap(long, default_value = "mainnet")]
        network: String,
    },
    /// Decode a Tari address
    DecodeAddress {
        /// The Tari address to decode
        address: String,
    },
} 