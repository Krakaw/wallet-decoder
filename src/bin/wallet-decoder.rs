use clap::Parser;
use tari_address_generator::{network::Network, wallet::TariWalletError, TariAddressGenerator};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Generate a new Tari wallet
    Generate {
        /// Optional password for the wallet
        #[clap(long, short = 'P')]
        password: Option<String>,

        /// Network to use (default: mainnet)
        #[clap(long, default_value = "mainnet")]
        network: String,

        /// Optional payment_id
        #[clap(long, short)]
        payment_id: Option<String>,
    },
    /// Decode a Tari address
    Decode {
        /// The Tari address to decode
        address: String,
    },
    /// Load a seed phrase and output addresses
    Load {
        /// The seed phrase to load (space-separated words)
        seed_phrase: String,

        /// Optional password for the wallet
        #[clap(long, short = 'P')]
        password: Option<String>,

        /// Network to use (default: mainnet)
        #[clap(long, default_value = "mainnet")]
        network: String,

        /// Optional payment_id
        #[clap(long, short)]
        payment_id: Option<String>,
    },
}

fn main() -> Result<(), TariWalletError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate {
            password,
            network,
            payment_id,
        } => {
            let network = Network::try_from(network)?;
            let wallet = TariAddressGenerator::with_passphrase(password);

            let address =
                wallet.generate_new_wallet(network, "http://localhost:9998".to_string())?;
            match payment_id {
                Some(payment_id) => {
                    let address =
                        address.create_integrated_address(payment_id.as_bytes().to_vec())?;
                    println!("{:#?}", address);
                }
                None => {
                    println!("{:#?}", address);
                }
            }
        }
        Command::Decode { address } => {
            let address = TariAddressGenerator::new().parse_address(&address)?;
            println!("Decoded address:");
            println!("Network: {}", address.network());
            println!("Base58: {}", address.to_base58());
            println!("Emoji: {}", address.to_emoji());

            if let Some(payment_id) = address.payment_id() {
                println!("Payment ID: {}", hex::encode(payment_id));
            }
        }
        Command::Load {
            seed_phrase,
            password,
            network,
            payment_id,
        } => {
            let network = Network::try_from(network)?;
            let wallet = TariAddressGenerator::with_passphrase(password)
                .restore_from_seed_phrase(&seed_phrase, network, "".to_string())
                ?;
            match payment_id {
                Some(payment_id) => {
                    let address =
                        wallet.create_integrated_address(payment_id.as_bytes().to_vec())?;
                    println!("{:#?}", address);
                }
                None => {
                    println!("{:#?}", wallet);
                }
            }
        }
    }

    Ok(())
}
