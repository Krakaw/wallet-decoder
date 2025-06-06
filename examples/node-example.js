const { init, WasmTariAddressGenerator } = require('../pkg/tari_address_generator');

async function main() {
    try {
        // Initialize the WASM module
        await init();
        
        // Create a new instance
        const generator = new WasmTariAddressGenerator();
        
        console.log('Generating new wallet...\n');
        // Generate a new wallet
        const wallet = generator.generate_new_wallet('mainnet');
        console.log('Generated wallet:');
        console.log('Base58 Address:', wallet.address_base58());
        console.log('Emoji Address:', wallet.address_emoji());
        console.log('Seed Phrase:', wallet.seed_phrase());
        console.log('Network:', wallet.network());
        console.log('View Private Key:', wallet.view_private_key_hex());
        console.log('Spend Private Key:', wallet.spend_private_key_hex());
        console.log('View Public Key:', wallet.view_public_key_hex());
        console.log('Spend Public Key:', wallet.spend_public_key_hex());
        
        console.log('\nParsing address...\n');
        // Parse an address
        const address = "🐢📟🚓🍋📌💨💋🎭👛🔔🐭🚢🐗🍔👙💼🎹🤡🐣👀🎪🌊🍳🐰💐📿💎🍔🐚🐞🤠🐔👽🐋🐷🐪🏭😎😎😇🍣😇🏭🙈👾🍩🔮🔬💼🍼👖🐯🎻🍺🤢😍🍊💯😈🦁📎🎠💄📎🌲🎺🍌";
        const parsed = generator.parse_address(address);
        console.log('\nParsed address:');
        console.log('Base58:', parsed.to_base58());
        console.log('Emoji:', parsed.to_emoji());
        console.log('Network:', parsed.network());
        console.log('Has Payment ID:', parsed.has_payment_id());
        
        console.log('\nLoading wallet from seed phrase...\n');
        // Load from seed phrase
        const seedPhrase = "cake travel dry battle raise put outdoor mention hunt zero ice spice sweet angry bind slice uphold scout spike car transfer weather merry original";
        const loadedWallet = generator.restore_from_seed_phrase(seedPhrase, 'mainnet');
        console.log('\nLoaded wallet:');
        console.log('Base58 Address:', loadedWallet.address_base58());
        console.log('Emoji Address:', loadedWallet.address_emoji());
        console.log('Seed Phrase:', loadedWallet.seed_phrase());
        console.log('Network:', loadedWallet.network());
        
        console.log('\nCreating new address with payment ID...\n');
        const newAddress = loadedWallet.new_address_with_payment_id('1234567890');
        console.log('New Address:', newAddress.to_base58());
        console.log('New Address Emoji:', newAddress.to_emoji());
        console.log('New Address Network:', newAddress.network());
        console.log('New Address Has Payment ID:', newAddress.has_payment_id());
        console.log('New Address Payment ID Hex:', newAddress.payment_id());
        // Convert from Uint8Array to ascii
        const paymentId = newAddress.payment_id();  
        console.log('New Address Payment ID ASCII:', paymentId.map(byte => String.fromCharCode(byte)).join(''));
        
    } catch (error) {
        console.error('Error:', error);
    }
}

main(); 