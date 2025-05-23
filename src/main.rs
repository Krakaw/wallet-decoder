mod cli;
mod wallet;
mod address;
mod utils;

use clap::Parser;
use cli::{Args, Command};

fn main() {
    let args = Args::parse();

    match args.command {
        Command::GenerateWallet { password, network } => {
            match wallet::generate_wallet(password, network.clone()) {
                Ok(wallet_info) => {
                    println!("Wallet created successfully!");
                    println!("\nSeed Words (SAVE THESE SECURELY):");
                    println!("{}", wallet_info.seed_words);
                    println!("\nView Key:");
                    println!("{}", wallet_info.view_key);
                    println!("\nSpend Key:");
                    println!("{}", wallet_info.spend_key);
                    println!("\nTari Address:");
                    println!("{}", wallet_info.address.to_emoji_string());
                    println!("\nTari Address (Base58):");
                    println!("{}", wallet_info.address.to_base58());
                    println!("\nNetwork: {}", wallet_info.network);
                }
                Err(e) => println!("Error generating wallet: {:#?}", e),
            }
        }
        Command::DecodeAddress { address } => {
            match address::decode_address(&address) {
                Ok(address) => address::print_address_details(&address),
                Err(e) => println!("Error decoding address: {:#?}", e),
            }
        }
        Command::LoadSeedPhrase { seed_phrase, network, password } => {
            match  wallet::load_wallet_from_seed_phrase(&seed_phrase, network.clone(), password) {
                Ok(wallet_info) => {
                    println!("Wallet loaded successfully!");
                    println!("\nSeed Words:");
                    println!("{}", wallet_info.seed_words);
                    println!("\nView Key:");
                    println!("{}", wallet_info.view_key);
                    println!("\nSpend Key:");
                    println!("{}", wallet_info.spend_key);
                    println!("\nTari Address:");
                    println!("{}", wallet_info.address.to_emoji_string());
                    println!("\nTari Address (Base58):");
                    println!("{}", wallet_info.address.to_base58());
                    println!("\nNetwork: {}", wallet_info.network);
                    println!("\nPublic View Key:");
                    println!("{:?}", wallet_info.address.public_view_key());
                }
                Err(e) => println!("Error loading wallet: {:#?}", e),
            }
        }
    }
}
