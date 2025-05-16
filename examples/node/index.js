const fs = require('fs');
const path = require('path');

async function main() {
    // Import the WASM module
    const wasmModule = await import('../../pkg/wallet_decoder.js');

    // Example Tari addresses to decode
    const addresses = [
        "143BKvG9pF8uSpB2JrB6myLMJLjjjrAPzcUyaBWpWoYW3x3Vv1EncTVTSGpdRhvucBzGisRj17tQyfg6vkGWKGjvUxZ",
    ];

    console.log('Decoding Tari addresses...\n');

    for (const address of addresses) {
        try {
            console.log(`Address: ${address}`);
            const result = wasmModule.decode_tari_address(address);
            console.log('Decoded result:');
            console.log(JSON.stringify(result, null, 2));
            console.log('\n' + '-'.repeat(80) + '\n');
        } catch (error) {
            console.error(`Error decoding address ${address}:`, error.message);
        }
    }
}

main().catch(console.error); 