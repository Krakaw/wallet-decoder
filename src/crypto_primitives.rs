use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul};
use blake2::{Blake2b512, Digest as Blake2Digest};
use sha2::{Digest as Sha2Digest, Sha512};
use crate::common_types::Commitment;
use crate::transactions::transaction_components::transaction_output::RangeProof;

pub const N_BITS: usize = 64;
pub const M_PARTIES: usize = 1;
pub const MAX_PROOF_POINTS: usize = N_BITS * M_PARTIES;

#[derive(Debug, Clone)]
pub struct Challenges {
    pub y: Scalar,
    pub z: Scalar,
    pub x: Scalar,
    pub u: Scalar, // Challenge for the inner-product proof aggregation
}

pub fn get_g_base() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(b"TARI_LIGHTWALLET_BP_G_BASE_202310")
}

pub fn get_h_base() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(b"TARI_LIGHTWALLET_BP_H_BASE_202310")
}

pub fn get_bulletproof_generators_g_h_vec(n: usize) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>) {
    let mut g_vec = Vec::with_capacity(n);
    let mut h_vec = Vec::with_capacity(n);

    for i in 0..n {
        let g_domain_sep = format!("TARI_LW_BP_G_VEC_IDX_{}_202310", i);
        let h_domain_sep = format!("TARI_LW_BP_H_VEC_IDX_{}_202310", i);

        g_vec.push(RistrettoPoint::hash_from_bytes::<Sha512>(g_domain_sep.as_bytes()));
        h_vec.push(RistrettoPoint::hash_from_bytes::<Sha512>(h_domain_sep.as_bytes()));
    }
    (g_vec, h_vec)
}

pub fn reconstruct_challenges(
    proof: &RangeProof,
    commitment_to_value: &Commitment,
) -> Result<Challenges, String> {
    let mut hasher = Blake2b512::new();

    // --- Generate y ---
    hasher.update(b"bulletproof_plus_y_challenge_domain_sep");
    hasher.update(proof.a.as_bytes());
    hasher.update(proof.a1.as_bytes());
    hasher.update(proof.b.as_bytes());
    hasher.update(commitment_to_value.0);
    let hash_y_bytes: [u8; 64] = hasher.finalize_reset().into();
    let y = Scalar::from_bytes_mod_order_wide(&hash_y_bytes);

    // --- Generate z ---
    hasher.update(b"bulletproof_plus_z_challenge_domain_sep");
    hasher.update(y.as_bytes());
    hasher.update(proof.a.as_bytes());
    hasher.update(proof.a1.as_bytes());
    hasher.update(proof.b.as_bytes());
    hasher.update(commitment_to_value.0);
    let hash_z_bytes: [u8; 64] = hasher.finalize_reset().into();
    let z = Scalar::from_bytes_mod_order_wide(&hash_z_bytes);

    // --- Generate x ---
    hasher.update(b"bulletproof_plus_x_challenge_domain_sep");
    hasher.update(y.as_bytes());
    hasher.update(z.as_bytes());
    hasher.update(proof.a.as_bytes());
    hasher.update(proof.a1.as_bytes());
    hasher.update(proof.b.as_bytes());
    hasher.update(commitment_to_value.0);
    let hash_x_bytes: [u8; 64] = hasher.finalize_reset().into(); // Reset for u's hasher or if more challenges followed
    let x = Scalar::from_bytes_mod_order_wide(&hash_x_bytes);

    // --- Generate u (IPP challenge) ---
    // Using finalize_reset for x's hash means 'hasher' is ready.
    // However, IPP often uses its own transcript or a very clear domain separation.
    // Re-initializing or using a separate hasher for 'u' is safer.
    let mut ipp_hasher = Blake2b512::new();
    ipp_hasher.update(b"bulletproof_plus_ipp_u_challenge_domain_sep");
    for l_point_compressed in &proof.li {
        ipp_hasher.update(l_point_compressed.as_bytes());
    }
    for r_point_compressed in &proof.ri {
        ipp_hasher.update(r_point_compressed.as_bytes());
    }
    ipp_hasher.update(y.as_bytes());
    ipp_hasher.update(z.as_bytes());
    ipp_hasher.update(x.as_bytes());

    let hash_u_bytes: [u8; 64] = ipp_hasher.finalize().into();
    let u = Scalar::from_bytes_mod_order_wide(&hash_u_bytes);

    Ok(Challenges { y, z, x, u })
}

pub fn verify_multiscalar_multiplication(
    proof: &RangeProof,
    commitment: &Commitment,
    challenges: &Challenges,
) -> Result<(), String> {
    let g_base = get_g_base();
    let h_base = get_h_base();
    let (g_vec, h_vec) = get_bulletproof_generators_g_h_vec(MAX_PROOF_POINTS);

    let c_point = CompressedRistretto(commitment.0).decompress()
        .ok_or_else(|| "Failed to decompress commitment point C".to_string())?;
    let proof_a = proof.a.decompress()
        .ok_or_else(|| "Failed to decompress proof point A".to_string())?;
    let proof_a1 = proof.a1.decompress()
        .ok_or_else(|| "Failed to decompress proof point A1".to_string())?;
    let proof_b = proof.b.decompress()
        .ok_or_else(|| "Failed to decompress proof point B".to_string())?;

    let mut li_points: Vec<RistrettoPoint> = Vec::with_capacity(proof.li.len());
    for (i, l_comp) in proof.li.iter().enumerate() {
        li_points.push(l_comp.decompress().ok_or_else(|| format!("Failed to decompress proof.li point at index {}", i))?);
    }
    let mut ri_points: Vec<RistrettoPoint> = Vec::with_capacity(proof.ri.len());
    for (i, r_comp) in proof.ri.iter().enumerate() {
        ri_points.push(r_comp.decompress().ok_or_else(|| format!("Failed to decompress proof.ri point at index {}", i))?);
    }

    let y = challenges.y;
    let z = challenges.z;
    let x = challenges.x;
    let u = challenges.u;

    let z_sq = z * z;
    let z_cub = z_sq * z;

    let y_inv = y.invert();
    let mut y_inv_powers = vec![Scalar::ONE; MAX_PROOF_POINTS];
    if MAX_PROOF_POINTS > 0 {
        y_inv_powers[0] = y_inv;
        for i in 1..MAX_PROOF_POINTS {
            y_inv_powers[i] = y_inv_powers[i-1] * y_inv;
        }
    }

    let mut points: Vec<RistrettoPoint> = Vec::with_capacity(7 + 2 * MAX_PROOF_POINTS + 2 * RangeProof::PROOF_M_VALUE);
    let mut scalars: Vec<Scalar> = Vec::with_capacity(points.capacity());

    points.push(proof_a);   scalars.push(Scalar::ONE);
    points.push(proof_a1);  scalars.push(x);
    points.push(c_point);   scalars.push(-z_sq);
    points.push(proof_b);   scalars.push(-x);

    points.push(g_base); scalars.push(proof.r1 * x * proof.s1);
    points.push(h_base); scalars.push(proof.r1 * y * proof.s1 + z_cub * proof.d1);

    let mut two_powers = vec![Scalar::ONE; N_BITS];
    if N_BITS > 0 {
        let two = Scalar::from(2u8);
        for i in 1..N_BITS {
            two_powers[i] = two_powers[i-1] * two;
        }
    }

    for i in 0..MAX_PROOF_POINTS {
        points.push(g_vec[i]);
        scalars.push(-z * y_inv_powers[i]); // Scalar for G_i

        points.push(h_vec[i]);
        // Scalar for H_i: y_inv_powers[i] * (-z^2 - z^3 * 2^i)
        let h_scalar_term = -z_sq - z_cub * two_powers[i];
        scalars.push(y_inv_powers[i] * h_scalar_term);
    }

    let u_inv = u.invert();
    let mut u_powers = vec![Scalar::ONE; proof.li.len()];
    let mut u_inv_powers = vec![Scalar::ONE; proof.ri.len()];

    if !proof.li.is_empty() {
      // u_powers[0] is already Scalar::ONE if needed, or u if starting power is 1
      // If loop starts from 0 for u_powers[0] = u^0, then no change.
      // If loop starts from 1 for u_powers[0] = u, then init with u.
      // Current code results in [1, u, u^2, ...], which is fine if IPP formula expects u^0 for first L.
      // Often IPP challenges are u_j, u_j_inv, so u_powers[j] and u_inv_powers[j].
      for i in 1..proof.li.len() { // if proof.li.len() == 1, this loop is skipped.
          u_powers[i] = u_powers[i-1] * u;
      }
      // If proof.li.len() == 0, u_powers is empty.
      // If proof.li.len() == 1, u_powers is [1].
    }
    if !proof.ri.is_empty() {
      for i in 1..proof.ri.len() {
          u_inv_powers[i] = u_inv_powers[i-1] * u_inv;
      }
    }

    for (j, l_point) in li_points.iter().enumerate() {
        points.push(*l_point); scalars.push(u_powers[j]);
    }
    for (j, r_point) in ri_points.iter().enumerate() {
        points.push(*r_point); scalars.push(u_inv_powers[j]);
    }

    let check_point = RistrettoPoint::multiscalar_mul(&scalars, &points);

    if check_point.is_identity() {
        Ok(())
    } else {
        Err("Multiscalar multiplication check failed. Result was not identity.".to_string())
    }
}
