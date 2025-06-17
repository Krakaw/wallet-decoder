// Copyright 2024. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use tari_crypto::ristretto::RangeProof as CryptoRangeProof;

/// Range proof for a UTXO
#[derive(Debug, Clone, Default)]
pub struct RangeProof(pub CryptoRangeProof);
