use clap::Parser;
use tari_address_generator::{network::Network, TariAddressGenerator};

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
        
        /// Show detailed component breakdown with hex data
        #[clap(long, short)]
        breakdown: bool,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate {
            password,
            network,
            payment_id,
        } => {
            let network = Network::try_from(network)?;
            let wallet = TariAddressGenerator::with_passphrase(password);

            let address = wallet.generate_new_wallet(network)?;
            match payment_id {
                Some(payment_id) => {
                    let address = address.create_integrated_address(payment_id.as_bytes().to_vec())?;
                    println!("{:#?}", address);
                }
                None => {
                    println!("{:#?}", address);
                }
            }
        }
        Command::Decode { address, breakdown } => {
            let generator = TariAddressGenerator::new();
            
            if breakdown {
                // Use component breakdown for detailed error analysis
                match generator.parse_address_with_breakdown(&address) {
                    Ok(address) => {
                        println!("✓ Address is valid!");
                        println!("Network: {}", address.network());
                        println!("Base58: {}", address.to_base58());
                        println!("Emoji: {}", address.to_emoji());
                        if let Some(payment_id) = address.payment_id() {
                            println!("Payment ID: {}", hex::encode(payment_id));
                        }
                    }
                    Err(e) => {
                        println!("{}", e);
                        return Err(e.into());
                    }
                }
            } else {
                // Use standard parsing with detailed errors
                let address = generator.parse_address(&address)?;
                println!("Decoded address:");
                println!("Network: {}", address.network());
                println!("Base58: {}", address.to_base58());
                println!("Emoji: {}", address.to_emoji());

                if let Some(payment_id) = address.payment_id() {
                    println!("Payment ID: {}", hex::encode(payment_id));
                }
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
                .restore_from_seed_phrase(&seed_phrase, network)?;
            match payment_id {
                Some(payment_id) => {
                    let address = wallet.create_integrated_address(payment_id.as_bytes().to_vec())?;
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
