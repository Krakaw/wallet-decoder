/// Damm algorithm implementation for checksum calculation
/// This uses the quasigroup table from the original JavaScript implementation
use once_cell::sync::Lazy;


/// The number of bytes used for the checksum
/// This is included for applications that need to know it for encodings
pub const CHECKSUM_BYTES: usize = 1;

/// The reduction polynomial mask for Damm algorithm
/// Calculated from coefficients [4, 3, 1] as: 1 + (1 << 4) + (1 << 3) + (1 << 1)
const COEFFICIENTS: [u8; 3] = [4, 3, 1];
static MASK: Lazy<u8> = Lazy::new(|| {
    let mut mask = 1u8;

    for bit in COEFFICIENTS {
        let shift = 1u8.checked_shl(u32::from(bit)).unwrap();
        mask = mask.checked_add(shift).unwrap();
    }

    mask
});

/// Compute the DammSum checksum for a byte slice
pub fn compute_checksum(data: &[u8]) -> u8 {
    // Perform the Damm algorithm
    let mut result = 0u8;

    for digit in data {
        result ^= *digit; // add
        let overflow = (result & (1 << 7)) != 0;
        result <<= 1; // double
        if overflow {
            // reduce
            result ^= *MASK;
        }
    }

    result
}

/// Verify Damm checksum
pub fn verify_damm_checksum(data: &[u8], checksum: u8) -> bool {
    compute_checksum(data) == checksum
}

/// Calculate and append Damm checksum to data
pub fn append_damm_checksum(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    let checksum = compute_checksum(data);
    result.push(checksum);
    result
}

/// Verify data with appended checksum
pub fn verify_data_with_checksum(data_with_checksum: &[u8]) -> bool {
    if data_with_checksum.is_empty() {
        return false;
    }
    
    let data_len = data_with_checksum.len() - 1;
    let data = &data_with_checksum[..data_len];
    let checksum = data_with_checksum[data_len];
    
    verify_damm_checksum(data, checksum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_data() {
        assert_eq!(compute_checksum(&[]), 0);
    }

    #[test]
    fn test_append_and_verify() {
        let data = vec![1, 2, 3, 4, 5];
        let data_with_checksum = append_damm_checksum(&data);
        assert!(verify_data_with_checksum(&data_with_checksum));
    }

    #[test]
    fn test_invalid_checksum() {
        let data = vec![1, 2, 3, 4, 5];
        let mut data_with_checksum = append_damm_checksum(&data);
        
        // Corrupt the checksum
        *data_with_checksum.last_mut().unwrap() = 9;
        
        assert!(!verify_data_with_checksum(&data_with_checksum));
    }

    #[test]
    fn test_checksum_verification() {
        let data = vec![0, 1, 2, 3];
        let checksum = compute_checksum(&data);
        assert!(verify_damm_checksum(&data, checksum));
        assert!(!verify_damm_checksum(&data, (checksum + 1) % 10));
    }
} 