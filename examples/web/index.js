import init, { decode_tari_address } from '../../pkg/wallet_decoder.js';

async function run() {
    await init();
    window.decodeAddress = async function() {
        const addressInput = document.getElementById('address');
        const resultDiv = document.getElementById('result');
        
        try {
            const address = addressInput.value.trim();
            if (!address) {
                resultDiv.textContent = 'Please enter a Tari address';
                return;
            }

            const result = decode_tari_address(address);
            resultDiv.textContent = JSON.stringify(result, null, 2);
        } catch (error) {
            resultDiv.textContent = `Error: ${error.message}`;
        }
    };
}

run().catch(console.error); 