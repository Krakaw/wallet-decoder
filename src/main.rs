mod cli;
mod wallet;
mod address;

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
    }
}
