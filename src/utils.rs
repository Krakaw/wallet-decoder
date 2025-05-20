/// Converts a Vec<u8> to an ASCII string.
/// Invalid ASCII bytes are replaced with the replacement character ().
pub fn bytes_to_ascii_string(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|&b| if b.is_ascii() { b as char } else { ' ' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_ascii_string() {
        // Test valid ASCII
        let valid_ascii = vec![72, 101, 108, 108, 111]; // "Hello"
        assert_eq!(bytes_to_ascii_string(&valid_ascii), "Hello");

        // Test invalid ASCII
        let invalid_ascii = vec![72, 101, 108, 108, 111, 255];
        assert_eq!(bytes_to_ascii_string(&invalid_ascii), "Hello ");

        // Test empty vector
        let empty: Vec<u8> = vec![];
        assert_eq!(bytes_to_ascii_string(&empty), "");

        // Test multiple invalid bytes
        let mixed = vec![72, 255, 101, 254, 108];
        assert_eq!(bytes_to_ascii_string(&mixed), "H e l");
    }
} 