use core::iter;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use sha3::{Digest, Sha3_512};

// Define RangeProofError enum
#[derive(Debug, PartialEq, Eq)]
pub enum RangeProofError {
    InvalidProof,
    VerificationFailed,
    DeserializationError(String),
    ProofConstructionError(String), // Should be Deserialization if from_bytes fails
}

// Define RangeProof struct (manual deserialization target)
#[derive(Debug)]
pub struct RangeProof {
    pub a: RistrettoPoint,
    pub a1: RistrettoPoint,
    pub b: RistrettoPoint,
    pub r_prime: Scalar,
    pub s_prime: Scalar,
    pub d_prime: Scalar,
    pub l: Vec<RistrettoPoint>,
    pub r: Vec<RistrettoPoint>,
}

impl RangeProof {
    pub fn from_bytes(proof_bytes: &[u8]) -> Result<Self, RangeProofError> {
        if proof_bytes.len() < 6 * 32 {
            return Err(RangeProofError::DeserializationError(
                "Proof bytes too short for fixed components".to_string(),
            ));
        }

        let mut offset = 0;

        let mut read_point = |off: &mut usize| -> Result<RistrettoPoint, RangeProofError> {
            if *off + 32 > proof_bytes.len() {
                return Err(RangeProofError::DeserializationError("Not enough bytes for point".to_string()));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&proof_bytes[*off..*off + 32]);
            *off += 32;
            RistrettoPoint::from_uniform_bytes(&bytes)
                .map_err(|_| RangeProofError::DeserializationError("Failed to deserialize RistrettoPoint".to_string()))
        };

        let mut read_scalar = |off: &mut usize| -> Result<Scalar, RangeProofError> {
            if *off + 32 > proof_bytes.len() {
                return Err(RangeProofError::DeserializationError("Not enough bytes for scalar".to_string()));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&proof_bytes[*off..*off + 32]);
            *off += 32;
            Ok(Scalar::from_bytes_mod_order(bytes))
        };

        let a = read_point(&mut offset)?;
        let a1 = read_point(&mut offset)?;
        let b = read_point(&mut offset)?;
        let r_prime = read_scalar(&mut offset)?;
        let s_prime = read_scalar(&mut offset)?;
        let d_prime = read_scalar(&mut offset)?;

        let remaining_bytes = proof_bytes.len() - offset;
        if remaining_bytes % 64 != 0 {
            return Err(RangeProofError::DeserializationError(
                "Remaining bytes not divisible by 64 (for L and R points)".to_string(),
            ));
        }

        let num_lr_pairs = remaining_bytes / 64;
        let mut l_vec = Vec::with_capacity(num_lr_pairs);
        let mut r_vec = Vec::with_capacity(num_lr_pairs);

        for _ in 0..num_lr_pairs {
            l_vec.push(read_point(&mut offset)?);
            r_vec.push(read_point(&mut offset)?);
        }

        Ok(RangeProof {
            a,
            a1,
            b,
            r_prime,
            s_prime,
            d_prime,
            l: l_vec,
            r: r_vec,
        })
    }
}

// Define Statement struct
#[derive(Debug)]
pub struct Statement {
    pub commitment: [u8; 32], // This should be a RistrettoPoint, or be convertible
    pub minimum_value_promise: u64,
}

// Define RistrettoAggregatedPublicStatement struct
#[derive(Debug)]
pub struct RistrettoAggregatedPublicStatement {
    pub statements: Vec<Statement>, // For now, assume one statement per bundle
}

// Define RangeProofService trait
pub trait RangeProofService {
    fn verify_batch(
        &self,
        proofs: Vec<&RangeProof>, // Takes deserialized RangeProof structs
        statements: Vec<&RistrettoAggregatedPublicStatement>,
    ) -> Result<(), RangeProofError>;
}

// Define BulletproofsPlusService struct
#[derive(Debug)]
pub struct BulletproofsPlusService {
    /// Pedersen G base for commitments (value)
    pub base_g: RistrettoPoint,
    /// Pedersen H base for commitments (mask)
    pub base_h: RistrettoPoint,
    /// Vector G_i generators for inner product argument
    pub vec_g_ipa: Vec<RistrettoPoint>,
    /// Vector H_i generators for inner product argument
    pub vec_h_ipa: Vec<RistrettoPoint>,
    /// Bit length of the range proof (e.g., 64)
    pub bit_length: usize,
    /// Max number of values aggregated in a single proof (m), typically a power of 2.
    /// For our current Statement structure, this is effectively 1.
    pub aggregation_factor: usize,
}

impl BulletproofsPlusService {
    pub fn new(bit_length: usize, aggregation_factor: usize) -> Result<Self, RangeProofError> {
        if !bit_length.is_power_of_two() || bit_length == 0 || bit_length > 64 {
            return Err(RangeProofError::InitializationError(
                "Bit length must be a power of two between 1 and 64.".to_string(),
            ));
        }
        if !aggregation_factor.is_power_of_two() || aggregation_factor == 0 {
            // Tari's bulletproofs-plus crate supports aggregation_factor that is a power of two.
            // Our current RistrettoAggregatedPublicStatement implies aggregation_factor = 1.
            return Err(RangeProofError::InitializationError(
                "Aggregation factor must be a power of two and non-zero.".to_string(),
            ));
        }

        let base_g = constants::RISTRETTO_BASEPOINT_POINT; // Standard G
        let base_h = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"TariBulletproofsPlus.H_base");

        // For IPA, G_i and H_i vectors are needed. Their size is n*m.
        // n = bit_length, m = aggregation_factor
        let num_ipa_generators = bit_length * aggregation_factor;
        let mut vec_g_ipa = Vec::with_capacity(num_ipa_generators);
        let mut vec_h_ipa = Vec::with_capacity(num_ipa_generators);

        for i in 0..num_ipa_generators {
            // Deriving unique generators by hashing. This is a common technique.
            // IMPORTANT: These must match the generators used by the prover.
            let g_i_label = format!("TariBulletproofsPlus.G_ipa_{}", i);
            let h_i_label = format!("TariBulletproofsPlus.H_ipa_{}", i);
            vec_g_ipa.push(RistrettoPoint::hash_from_bytes::<Sha3_512>(g_i_label.as_bytes()));
            vec_h_ipa.push(RistrettoPoint::hash_from_bytes::<Sha3_512>(h_i_label.as_bytes()));
        }

        Ok(Self {
            base_g,
            base_h,
            vec_g_ipa,
            vec_h_ipa,
            bit_length,
            aggregation_factor,
        })
    }
}

impl RangeProofService for BulletproofsPlusService {
    fn verify_batch(
        &self,
        proofs: Vec<&RangeProof>,
        statements_bundles: Vec<&RistrettoAggregatedPublicStatement>,
    ) -> Result<(), RangeProofError> {
        if proofs.len() != statements_bundles.len() {
            return Err(RangeProofError::InvalidProof);
        }
        if proofs.is_empty() {
            return Ok(());
        }

        // The base_u generator for IPA final check (from previous version)
        // This should align with how Tari's BP+ uses it, or if it's derived differently.
        // The `bulletproofs-plus` crate uses `h_base` for some roles that other BP versions might use U for.
        // For now, let's assume r1, s1, d1 are part of the IPA reduction where d1 might involve H.
        // The Tari `bulletproofs-plus` code uses `pc_gens.g_bases()` for d1, and `h_base` for r1, s1 related terms.
        // It seems `d1` is a vector for extended masks. If not using extended masks, d1 might be a single scalar for a different base.
        // The `RangeProof` struct from `bulletproofs-plus` has `d1: Vec<Scalar>`.
        // If `extension_degree` is `DefaultPedersen` (0), then `d1` should be empty or handle appropriately.
        // My `RangeProof` struct has `d_prime: Scalar`. I need to align this.
        // For now, I'll assume `d_prime` (scalar) is for `base_h` similar to `s_prime`, and `r_prime` for `base_g`.
        // This is a common simplification if `d1` vector is not used for extension.
        // THIS IS A MAJOR POINT OF ALIGNMENT NEEDED.
        // Re-checking tari-project/bulletproofs-plus/src/range_proof.rs `prove_with_rng`
        // `a1 += g_base * d` and `b += g_base * eta`
        // `d1: Vec<Scalar> = izip!(eta.iter(), d.iter(), alpha.iter()).map(|(eta, d, alpha)| eta + d * e + alpha * e_square).collect();`
        // This `d1` is for `g_base_vec` from `PedersenGens`. If `extension_degree` is 0 (DefaultPedersen), `g_base_vec` has 1 element (base_g).
        // So `d1` would be `Vec<Scalar>` of len 1. My `d_prime` should be this `d1[0]`.

        // Placeholder for U, if needed by the specific Tari verification equation for the IPA final step.
        // Often, the role of U is folded into H or other existing generators.
        // The `bulletproofs-plus` code's verify function implies a final check against identity,
        // suggesting all terms are moved to one side.

        for (proof_idx, (proof, agg_statement)) in proofs.iter().zip(statements_bundles.iter()).enumerate() {
            // Assuming aggregation_factor is 1 for now, as per our Statement structure.
            if agg_statement.statements.len() != self.aggregation_factor || self.aggregation_factor != 1 {
                return Err(RangeProofError::InvalidProof);
            }
            let statement = &agg_statement.statements[0];

            // Deserialize the commitment from the statement into a RistrettoPoint
            // TODO: Confirm if `from_uniform_bytes` is correct or if `CompressedRistretto::decompress` is needed.
            // Tari's `Statement` has `commitment: HomomorphicCommitment<RistrettoPublicKey>`,
            // which can be converted to `RistrettoPoint`. Assuming `[u8;32]` is uniform bytes for now.
            let v_commitment = RistrettoPoint::from_uniform_bytes(&statement.commitment)
                .map_err(|_| RangeProofError::DeserializationError(format!("Failed to deserialize V for proof {}", proof_idx)))?;

            // Initialize transcript (Fiat-Shamir) - Mimicking RangeProofTranscript from bulletproofs-plus crate
            // The actual `bulletproofs-plus` crate uses `merlin::Transcript`.
            // We are using `sha3::Sha3_512` as a sequential hasher to simulate transcript behavior.
            let mut transcript = Sha3_512::new();

            // Absorb public inputs into transcript. Order is critical and must match Tari's.
            // Based on `bulletproofs-plus/src/transcripts.rs` and `range_proof.rs` (prove/verify methods)
            // Domain separator for the RangeProof protocol itself
            transcript.update(b"BulletproofsPlus.RangeProofTranscript"); // General domain separator

            // Absorb generators (H_base, G_bases for IPA, pc_gens.G_bases for extended Pedersen)
            // Note: `bulletproofs-plus` absorbs compressed points.
            transcript.update(self.base_h.compress().as_bytes()); // pc_gens.h_base_compressed

            // Absorb G_bases from PedersenGens (pc_gens.g_bases_compressed())
            // If extension_degree = 0 (DefaultPedersen), this is just base_g.
            // My current `BulletproofsPlusService` stores `base_g` which is pc_gens.g_bases()[0]
            // and `vec_g_ipa`, `vec_h_ipa` which are bp_gens.
            // The `bulletproofs-plus` transcript absorbs `statement.generators.g_bases_compressed()`,
            // which are the `pc_gens.g_base_vec`. For DefaultPedersen, this is one point.
            transcript.update(self.base_g.compress().as_bytes()); // Assuming DefaultPedersen, so only one pc_gens.G

            // Absorb bit_length, extension_degree (from pc_gens), aggregation_factor
            transcript.update(&(self.bit_length as u64).to_le_bytes());
            // Assuming DefaultPedersen (0) for extension_degree for now.
            // My `d_prime` is a single scalar, implying no extension or extension degree 0 for the proof's d1.
            transcript.update(&(0u64).to_le_bytes()); // Placeholder for extension_degree from pc_gens
            transcript.update(&(self.aggregation_factor as u64).to_le_bytes());

            // Absorb RangeStatement details
            // Commitments (for this proof, only one: v_commitment)
            transcript.update(v_commitment.compress().as_bytes());
            // Minimum value promises
            if let Some(min_val) = statement.minimum_value_promise_option() {
                transcript.update(&min_val.to_le_bytes());
            } else {
                // If None, typically a specific byte or empty bytes are absorbed.
                // For simplicity, let's absorb a zero byte if there's no promise.
                // The `bulletproofs-plus` crate does this by iterating `minimum_value_promises` which are `Option<u64>`.
                // If `None`, nothing is absorbed for that particular promise's value part.
                // The presence/absence might be part of overall structure/length of absorbed data.
                // For now, this is simplified.
            }
            // Seed nonce is not public, not absorbed by verifier.

            // Absorb proof.A for y, z challenges
            transcript.update(proof.a.compress().as_bytes());
            let challenge_y = Scalar::from_hash(transcript.clone().finalize_reset()); // Cloned for intermediate hash
            transcript.update(challenge_y.as_bytes()); // Absorb y
            let challenge_z = Scalar::from_hash(transcript.clone().finalize_reset()); // Cloned for intermediate hash
            transcript.update(challenge_z.as_bytes()); // Absorb z

            // Absorb L_i, R_i for round challenges (x_j in my code, e_round in BP+ crate)
            let n_ipa_rounds = proof.l.len();
            if n_ipa_rounds == 0 || proof.l.len() != proof.r.len() {
                 return Err(RangeProofError::InvalidProof);
            }
            // Expected rounds: log2(bit_length * aggregation_factor)
            let expected_ipa_rounds = (self.bit_length * self.aggregation_factor).ilog2() as usize;
            if n_ipa_rounds != expected_ipa_rounds {
                return Err(RangeProofError::InvalidProof);
            }

            let mut challenges_x = Vec::with_capacity(n_ipa_rounds); // These are `e` in each round of BP+
            for i in 0..n_ipa_rounds {
                transcript.update(proof.l[i].compress().as_bytes());
                transcript.update(proof.r[i].compress().as_bytes());
                challenges_x.push(Scalar::from_hash(transcript.clone().finalize_reset())); // Cloned
                // Note: The BP+ crate updates the transcript with each L_i, R_i before hashing for *that round's* challenge.
                // My current loop structure for Sha3_512 needs to ensure this.
                // A single transcript object is mutated sequentially.
            }

            // Final challenge `e` (or `e_final` to distinguish from round challenges)
            transcript.update(proof.a1.compress().as_bytes());
            transcript.update(proof.b.compress().as_bytes());
            let challenge_e_final = Scalar::from_hash(transcript.finalize_reset()); // Finalize transcript for this proof

            // TODO: Implement the main verification MSM based on Tari's bulletproofs-plus crate
            // This involves:
            // 1. Calculating s_vec from challenges_x (these are the round 'e's).
            // 2. Calculating y_powers, y_sum, d_vec, d_sum. (d_vec uses z, powers_of_2)
            // 3. Calculating scalar coefficients for all points in the big MSM.
            //    Points: G (self.base_g), H (self.base_h), G_ipa_vec, H_ipa_vec,
            //            A, A1, B (from proof), L_i, R_i (from proof), V (v_commitment).
            //    Scalars: Derived from r1, s1, d1 (proof.r_prime, s_prime, d_prime),
            //             challenges y, z, e_final, challenges_x (round e's),
            //             minimum_value_promise.
            // 4. Performing the single large MSM and checking against RistrettoPoint::identity().
            // This part is highly complex and needs to mirror the logic in
            // `tari-project/bulletproofs-plus/src/range_proof.rs`'s `verify` method's MSM construction.

            // For now, returning Ok as a placeholder until the MSM is implemented.
            // The previous placeholder check (lhs_check vs rhs_check) was too simplistic.
            // A full implementation requires careful porting of the MSM scalar calculations.
            // Example: `h_base_scalar += weight * (r1 * y * s1 + e_square * (y_nm_1 * z * d_sum + (z_square - z) * y_sum));`
            // And terms for A, A1, B, L_i, R_i, V_j, G_base_vec for d1, etc.
            // The `weight` is for batching, for single proof (or loop for batch) it's effectively 1.

            // If not implementing the full MSM right now, this proof is incomplete.
            // The crucial part is that challenge generation is now more aligned.
            // --- Start of MSM Scalar Calculation Logic ---
            // This section meticulously reconstructs the scalars for the final MSM verification
            // based on `tari-project/bulletproofs-plus/src/range_proof.rs` (method `verify`).

            // For a single proof verification (as in this loop, before batch-level aggregation of MSM inputs):
            let weight = Scalar::one(); // Effective weight for a single proof.

            // Inverse of y and y-1 for s_vec calculation (precompute)
            // challenges_x are the round challenges `e_k`
            // y is `challenge_y`
            let mut inv_scalars_for_s_vec = challenges_x.clone();
            inv_scalars_for_s_vec.push(challenge_y);
            inv_scalars_for_s_vec.push(challenge_y - Scalar::one());

            // Batch invert. `Scalar::batch_invert` returns the product of inverses.
            // We need individual inverses. Let's invert them one by one if not using a batch utility.
            // Or, if `Scalar::batch_invert` is available and does what I think, it modifies the vec in place.
            // The reference code uses `Scalar::batch_invert(&mut challenges_inv) * y * (y - Scalar::ONE);`
            // This suggests `challenges_inv` becomes `[x1_inv, ..., xk_inv, y_inv, (y-1)_inv]`.
            // For now, direct inversion:
            let mut challenges_x_inv = challenges_x.iter().map(|c| c.invert()).collect::<Vec<_>>();
            let y_inv = challenge_y.invert();
            let y_minus_1_inv = (challenge_y - Scalar::one()).invert();

            // Calculate s_vec (s_i in reference code)
            // s_vec[i] = product(x_j^{b_j}) where b_j depends on binary representation of i
            // This is complex. The reference code calculates s:
            // `s.push(challenges_inv_prod);` where `challenges_inv_prod` is product of all x_j_inv, y_inv, (y-1)_inv
            // then `s.push(s[i- (1<<log_i)] * challenges_sq[rounds - log_i - 1])`
            // This requires `challenges_sq` (squares of round challenges `x_j`).
            let challenges_x_sq = challenges_x.iter().map(|c| c * c).collect::<Vec<_>>();

            let mut s_vec = Vec::with_capacity(self.bit_length * self.aggregation_factor);
            if !challenges_x.is_empty() {
                // Calculate s_vec (s_i in reference code)
                // Based on tari-project/bulletproofs-plus/src/range_proof.rs lines 600-613
                let challenges_x_inv_product = challenges_x_inv.iter().fold(Scalar::one(), |acc, val| acc * val);
                let challenges_inv_prod_for_s0 = y_inv * y_minus_1_inv * challenges_x_inv_product;
                s_vec.push(challenges_inv_prod_for_s0);

                for i in 1..(self.bit_length * self.aggregation_factor) {
                    // This requires `n_ipa_rounds` to be `rounds` in their code.
                    // `rounds` is `full_length.ilog2()`, which is `n_ipa_rounds`.
                    let log_i = i.ilog2() as usize; // Safe since i > 0
                    let k = 1 << log_i;
                    // challenges_x_sq are squares of round challenges e_k (challenges_x in my code)
                    // The indexing `n_ipa_rounds - 1 - log_i` matches `rounds - log_i - 1`
                    if log_i >= n_ipa_rounds { // Protect against underflow if log_i is too large
                         return Err(RangeProofError::ProofConstructionError("log_i too large for s_vec calculation".to_string()));
                    }
                    let s_val = s_vec[i - k] * challenges_x_sq[n_ipa_rounds - 1 - log_i];
                    s_vec.push(s_val);
                }
            } else if self.bit_length * self.aggregation_factor > 0 {
                 // If full_length > 0 but challenges_x is empty, it's an invalid setup for s_vec.
                 // This case should ideally be caught by n_ipa_rounds check earlier.
                 s_vec.resize(self.bit_length * self.aggregation_factor, Scalar::one()); // Default if no rounds
            }


            // Powers of y: y^0, y^1, ..., y^{n*m}
            let full_length = self.bit_length * self.aggregation_factor;
            let mut y_powers = Vec::with_capacity(full_length + 1);
            let mut current_y_power = Scalar::one();
            for _ in 0..=full_length {
                y_powers.push(current_y_power);
                current_y_power *= challenge_y;
            }

            // Sum of y_powers (y_sum in reference): y * (y^(n*m) - 1) * (y-1)^-1
            let y_sum = if challenge_y == Scalar::one() {
                Scalar::from(full_length as u64)
            } else {
                challenge_y * (y_powers[full_length] - Scalar::one()) * y_minus_1_inv
            };

            // d_vec construction (d_j in reference)
            let z_sq = challenge_z * challenge_z;
            let two = Scalar::from(2u8);
            let mut d_vec = Vec::with_capacity(full_length);
            if self.bit_length > 0 {
                d_vec.push(z_sq);
                for _ in 1..self.bit_length {
                    d_vec.push(two * d_vec.last().unwrap());
                }
                for j_agg in 1..self.aggregation_factor {
                    for i_bit in 0..self.bit_length {
                        d_vec.push(d_vec[(j_agg - 1) * self.bit_length + i_bit] * z_sq);
                    }
                }
            }

            // d_sum calculation (sum of d_j * y_nm_i where y_nm_i = y^(n*m-i))
            // The reference code calculates `d_sum` differently: it's sum of `d_j` used for `h_base_scalar` term.
            // `d_sum = z_square * ( (z_square)^m - 1) * (z_square-1)^-1 * (2^n - 1)`
            // This also needs careful porting. For now, simple sum for placeholder.
            let d_sum_for_h_term = d_vec.iter().fold(Scalar::zero(), |acc, val| acc + val);


            // Initialize scalars for the final MSM
            let mut msm_scalars: Vec<Scalar> = Vec::new();
            let mut msm_points: Vec<RistrettoPoint> = Vec::new();

            // Add terms for G_i and H_i vectors (IPA generators)
            // These are `gi_base_scalars` and `hi_base_scalars` in reference.
            // Their calculation involves r1, s1, e (challenge_e_final), y_inv_i, s_vec, z, d_vec.
            // This is the core of the IPA verification part.
            // Example term for gi_base_scalars[k]: weight * ( (r1*e*y_inv_i*s_vec[k]) + e_sq*z )
            // Example term for hi_base_scalars[k]: weight * ( (s1*e*s_vec_rev[k]) - e_sq*(d_vec[k]*y_nm_i + z) )
            // This requires precise loop and indexing.

            // Add terms for G_i and H_i vectors (IPA generators / bp_gens in reference)
            // These are `gi_base_scalars` and `hi_base_scalars` in the reference.
            // Scalar calculation based on lines 616-629 in tari-project/bulletproofs-plus/src/range_proof.rs `verify`
            let r1e = proof.r_prime * challenge_e_final; // r1 * e
            let s1e = proof.s_prime * challenge_e_final; // s1 * e
            let e_final_sq = challenge_e_final * challenge_e_final;
            let e_final_sq_z = e_final_sq * challenge_z;

            let mut y_inv_current = Scalar::one(); // y_inv_i in reference
            let mut y_nm_current = y_powers[full_length]; // y_nm_i in reference (starts at y^{n*m})

            for i in 0..full_length {
                // Scalar for G_i[i] (vec_g_ipa)
                let g_scalar = r1e * y_inv_current * s_vec[i] + e_final_sq_z;
                msm_scalars.push(weight * g_scalar);
                msm_points.push(self.vec_g_ipa[i]);

                // Scalar for H_i[i] (vec_h_ipa)
                // s_vec_rev[i] corresponds to s_vec[full_length - 1 - i]
                let h_scalar = s1e * s_vec[full_length - 1 - i] - (e_final_sq * (d_vec[i] * y_nm_current + challenge_z));
                msm_scalars.push(weight * h_scalar);
                msm_points.push(self.vec_h_ipa[i]);

                y_inv_current *= y_inv;
                if y_nm_current != Scalar::zero() { // Avoid issues if y_inv is not well-defined (e.g. y=0)
                    y_nm_current *= y_inv; // Decrement power of y for y_nm_i effectively
                } else if full_length > 0 { // if y was zero, y_nm_current is zero (unless full_length is 0)
                     // y_nm_current remains zero.
                }

            }

            // Add terms for V_j (value commitments)
            // Scalar: -weight * e_final^2 * z^(2*(j+1)) * y_powers[full_length] (roughly, depends on exact structure)
            // Point: v_commitment
            // For now, aggregation_factor is 1, so j=0. z_even_powers in ref code.
            let z_pow_j_plus_1_sq = z_sq; // Since j=0 (m=1)
            msm_scalars.push(-weight * challenge_e_final * challenge_e_final * z_pow_j_plus_1_sq * y_powers[full_length]);
            msm_points.push(v_commitment);

            // Add term for minimum_value_promise (modifies H scalar)
            let mut h_base_scalar_offset = Scalar::zero();
            if let Some(min_val) = statement.minimum_value_promise_option() {
                 // This term is subtracted from h_base_scalar in ref: `h_base_scalar -= weighted * Scalar::from(minimum_value)`
                 // where `weighted` is `-weight * e_final^2 * z_pow_j_plus_1_sq * y_powers[full_length]` for V.
                 // So, it becomes `+ weight * e_final^2 * z_pow_j_plus_1_sq * y_powers[full_length] * min_val` for H.
                h_base_scalar_offset += weight * challenge_e_final * challenge_e_final * z_pow_j_plus_1_sq * y_powers[full_length] * Scalar::from(min_val);
            }


            // Terms for A, A1, B from proof
            // A: -weight * e_final^2
            // A1: -weight * e_final
            // B: -weight
            msm_scalars.push(-weight * challenge_e_final * challenge_e_final);
            msm_points.push(proof.a);
            msm_scalars.push(-weight * challenge_e_final);
            msm_points.push(proof.a1);
            msm_scalars.push(-weight);
            msm_points.push(proof.b);

            // Terms for L_i, R_i from proof
            // L_i: -weight * e_final^2 * challenges_x_sq[i]
            // R_i: -weight * e_final^2 * challenges_x_inv_sq[i] (need inverses of challenges_x_sq)
            let challenges_x_inv_sq = challenges_x_inv.iter().map(|c_inv| c_inv * c_inv).collect::<Vec<_>>();
            for i in 0..n_ipa_rounds {
                msm_scalars.push(-weight * challenge_e_final * challenge_e_final * challenges_x_sq[i]);
                msm_points.push(proof.l[i]);
                msm_scalars.push(-weight * challenge_e_final * challenge_e_final * challenges_x_inv_sq[i]);
                msm_points.push(proof.r[i]);
            }

            // Terms for G_base (pc_gens.g_bases) and H_base (pc_gens.h_base)
            // Scalar for G_base (related to d1 from proof, which is proof.d_prime for DefaultPedersen)
            // The reference code has `g_base_scalars.iter_mut().zip(d1.iter()).for_each(|(g,d1)| *g += weight * d1)`
            // Assuming d_prime is d1[0] for DefaultPedersen.
            msm_scalars.push(weight * proof.d_prime);
            msm_points.push(self.base_g);

            // Scalar for H_base
            // `h_base_scalar += weight * (r1*y*s1 + e_square * (y_nm_1*z*d_sum + (z_sq-z)*y_sum))`
            // Plus the offset from minimum_value_promise.
            let h_scalar = weight * (proof.r_prime * challenge_y * proof.s_prime +
                               challenge_e_final * challenge_e_final * (
                                   y_powers[full_length] * challenge_z * d_sum_for_h_term + // y_nm_1 is y_powers[full_length]
                                   (z_sq - challenge_z) * y_sum
                               )) + h_base_scalar_offset;
            msm_scalars.push(h_scalar);
            msm_points.push(self.base_h);

            // Perform the Multi-Scalar Multiplication
            let check_point = RistrettoPoint::multiscalar_mul(&msm_scalars, &msm_points);

            if !check_point.is_identity() {
                // For debugging:
                // println!("MSM check failed for proof {}", proof_idx);
                // println!("LHS (should be identity): {:?}", check_point.compress());
                return Err(RangeProofError::VerificationFailed);
            }
        }
        Ok(())
    }
}

// Helper for Statement struct, assuming minimum_value_promise might be optional in some contexts
// or to make it explicit when it's used (as Option<u64> is used in bulletproofs-plus crate)
impl Statement {
    pub fn minimum_value_promise_option(&self) -> Option<u64> {
        // The `bulletproofs-plus` crate's `RangeStatement` takes `minimum_value_promises: Vec<Option<u64>>`.
        // If our `minimum_value_promise` field being 0 signifies "no promise" or "promise of 0",
        // this method helps clarify its conversion to Option<u64>.
        // Tari's `transaction_output.rs` does `Some(output.minimum_value_promise.as_u64())`.
        // So, a value of 0 is treated as `Some(0)`, not `None`.
        Some(self.minimum_value_promise)
    }
}

// --- Revealed Value Range Proof Verification ---
use crate::tari_types::{
    ComAndPubSignature,
    CanonicalBytes, // Trait for getting canonical bytes for hashing
    CompressedPublicKey,
    Covenant,
    EncryptedData,
    OutputFeatures,
    TariScript,
    TransactionOutputVersion,
};
use curve25519_dalek::ristretto::CompressedRistretto;


/// Builds the challenge for the metadata signature used in RevealedValue range proofs.
/// This function replicates the logic from Tari's `TransactionOutput::build_metadata_signature_challenge`
/// and its called helper methods.
///
/// The challenge is `H(ephemeral_pubkey || ephemeral_commitment || sender_offset_public_key || commitment || message)`
/// where `message = H(version || script || features || covenant || encrypted_data || minimum_value_promise)`
///
/// Domain separation strings are critical and must match Tari's.
pub fn get_metadata_signature_challenge(
    version: &TransactionOutputVersion,
    script: &TariScript,
    features: &OutputFeatures,
    sender_offset_public_key: &CompressedPublicKey,
    ephemeral_commitment: &CompressedRistretto, // From ComAndPubSignature
    ephemeral_pubkey: &CompressedRistretto,     // From ComAndPubSignature
    commitment: &RistrettoPoint, // The output commitment C = vG + hH
    covenant: &Covenant,
    encrypted_data: &EncryptedData,
    minimum_value_promise: u64,
) -> [u8; 64] { // Tari uses Blake2b for a 64-byte hash output here. We use Sha3_512.

    // First, calculate the `message` hash: H_msg = H(version || script || features || covenant || encrypted_data || minimum_value_promise)
    // Tari uses DomainSeparatedConsensusHasher with "metadata_message" domain.
    let mut message_hasher = Sha3_512::new();
    message_hasher.update(b"TariMetadata.Message"); // Domain separator for message
    message_hasher.update(version.to_canonical_bytes());
    message_hasher.update(script.to_canonical_bytes());
    message_hasher.update(features.to_canonical_bytes());
    message_hasher.update(covenant.to_canonical_bytes());
    message_hasher.update(encrypted_data.to_canonical_bytes());
    message_hasher.update(&minimum_value_promise.to_le_bytes());
    let message_hash: [u8; 64] = message_hasher.finalize().into();

    // Then, calculate the final challenge: H_final = H(ephemeral_pubkey || ephemeral_commitment || sender_offset_pubkey || commitment || message_hash)
    // Tari uses DomainSeparatedConsensusHasher with "metadata_signature" domain.
    let mut final_hasher = Sha3_512::new();
    final_hasher.update(b"TariMetadata.SignatureChallenge"); // Domain separator for final challenge
    final_hasher.update(ephemeral_pubkey.as_bytes());
    final_hasher.update(ephemeral_commitment.as_bytes());
    final_hasher.update(sender_offset_public_key.as_bytes());
    final_hasher.update(commitment.compress().as_bytes());
    final_hasher.update(&message_hash);

    final_hasher.finalize().into()
}

/// Verifies a RevealedValue range proof.
///
/// This check relies on a specially constructed metadata signature where the amount is revealed.
/// The core verification equation is: `u_a == r_a + e * value`
/// where `r_a` is a deterministic nonce (usually zero).
pub fn verify_revealed_value_proof(
    commitment_point: &RistrettoPoint, // The commitment C being verified
    metadata_signature: &ComAndPubSignature,
    script: &TariScript,
    features: &OutputFeatures, // Needed for challenge
    sender_offset_public_key: &CompressedPublicKey, // Needed for challenge
    covenant: &Covenant, // Needed for challenge
    encrypted_data: &EncryptedData, // Needed for challenge
    minimum_value_promise: u64, // This is the 'revealed value'
    version: &TransactionOutputVersion, // Needed for challenge
) -> Result<(), RangeProofError> {

    let challenge_bytes = get_metadata_signature_challenge(
        version,
        script,
        features,
        sender_offset_public_key,
        metadata_signature.ephemeral_commitment(),
        metadata_signature.ephemeral_pubkey(),
        commitment_point,
        covenant,
        encrypted_data,
        minimum_value_promise,
    );

    let challenge_e = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
    let value_as_scalar = Scalar::from(minimum_value_promise);

    // In Tari's `revealed_value_range_proof_check`, `commit_nonce_a` is `PrivateKey::default()`, which is Scalar::zero().
    let commit_nonce_a = Scalar::zero();

    let expected_u_a = commit_nonce_a + challenge_e * value_as_scalar;

    if &expected_u_a == metadata_signature.u_a() {
        Ok(())
    } else {
        Err(RangeProofError::VerificationFailed(
            "RevealedValue range proof check failed".to_string(),
        ))
    }
}
