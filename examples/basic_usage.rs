use tari_address_generator::{TariAddressGenerator, Network};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new address generator
    let generator = TariAddressGenerator::new();
    
    println!("🚀 Tari Address Generator Demo\n");
    
    // Generate a new wallet for MainNet
    println!("📝 Generating new wallet for MainNet...");
    let wallet = generator.generate_new_wallet(Network::MainNet)?;
    
    println!("✅ Wallet generated successfully!\n");
    
    // Display wallet information
    println!("🔑 Wallet Information:");
    println!("├─ Network: {}", wallet.network());
    println!("├─ View Private Key: {}", wallet.view_private_key_hex());
    println!("├─ View Public Key: {}", wallet.view_public_key_hex());
    println!("├─ Spend Public Key: {}", wallet.spend_public_key_hex());
    println!("└─ Seed Phrase: {}\n", wallet.seed_phrase());
    
    // Display address formats
    println!("📍 Address Formats:");
    println!("├─ Base58: {}", wallet.address_base58());
    println!("└─ Emoji: {}\n", wallet.address_emoji());
    
    // Create an integrated address with payment ID
    println!("🔗 Creating integrated address with payment ID...");
    let payment_id = b"invoice_12345".to_vec();
    let integrated_address = wallet.create_integrated_address(payment_id.clone())?;
    
    println!("✅ Integrated address created!");
    println!("├─ Payment ID: {:?}", std::str::from_utf8(&payment_id).unwrap());
    println!("├─ Base58: {}", integrated_address.to_base58());
    println!("└─ Emoji: {}\n", integrated_address.to_emoji());
    
    // Demonstrate wallet restoration
    println!("🔄 Testing wallet restoration...");
    let seed_phrase = wallet.seed_phrase().to_string();
    let restored_wallet = generator.restore_from_seed_phrase(&seed_phrase, Network::MainNet)?;
    
    // Verify restoration worked correctly
    assert_eq!(wallet.address_base58(), restored_wallet.address_base58());
    println!("✅ Wallet restored successfully - addresses match!\n");
    
    // Generate wallets for different networks
    println!("🌍 Generating addresses for different networks:");
    for network in [Network::MainNet, Network::NextNet, Network::Esmeralda] {
        let network_wallet = generator.generate_new_wallet(network)?;
        println!("├─ {} ({}): {}", 
                 network.name(), 
                 network.base58_prefix(),
                 &network_wallet.address_base58()[..20]); // Show first 20 chars
    }
    
    println!("\n🎉 Demo completed successfully!");
    
    Ok(())
} 