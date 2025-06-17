use clap::Parser;
use tari_address_generator::{
    utxo::{create_range_proof_service, scanner::UtxoScanner, verify_range_proof},
    Network, TariAddressGenerator, wallet::TariWalletError,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Seed phrase for wallet restoration
    #[arg(short = 's', long)]
    seed: String,

    /// Base node address (e.g., http://localhost:18142)
    #[arg(short, long, default_value = "http://localhost:18142")]
    base_node: String,
}

#[tokio::main]
async fn main() -> Result<(), TariWalletError> {
    let args = Args::parse();
    
    let utxo_scanner = UtxoScanner::new(args.base_node);
    let generator = TariAddressGenerator::new();

    // When generating or restoring, provide the base_node_address
    let wallet = generator.restore_from_seed_phrase(
        &args.seed,
        Network::MainNet,
    )?;
    let view_key_private = wallet.view_private_key();

    let utxos = utxo_scanner.scan_for_utxos(
        &view_key_private,
    ).await?;

    if utxos.is_empty() {
        println!("No UTXOs found for the given seed phrase.");
    } else {
        println!("Found {} UTXO(s). Verifying range proofs...", utxos.len());
        let range_proof_service = create_range_proof_service();
        for (i, utxo) in utxos.iter().enumerate() {
            println!("Verifying UTXO #{} (Hash: {})", i + 1, utxo.output_hash);
            match verify_range_proof(utxo, &range_proof_service) {
                Ok(_) => println!("  Range proof is VALID."),
                Err(e) => println!("  Range proof is INVALID: {:?}", e),
            }
        }
    }

    Ok(())
}