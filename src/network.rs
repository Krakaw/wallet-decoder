use crate::error::{TariError, Result};
use std::str::FromStr;

/// Tari network types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// MainNet (0x00) - Base58 prefix 'T', Emoji prefix 🐢
    MainNet,
    /// NextNet (0x02) - Base58 prefix 't', Emoji prefix ⏩  
    NextNet,
    /// Esmeralda (0x26) - Base58 prefix 'e', Emoji prefix 💎
    Esmeralda,
}

impl Network {
    /// Get the network byte identifier
    pub fn as_byte(&self) -> u8 {
        match self {
            Network::MainNet => 0x00,
            Network::NextNet => 0x02,
            Network::Esmeralda => 0x26,
        }
    }

    /// Create network from byte identifier
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(Network::MainNet),
            0x02 => Ok(Network::NextNet),
            0x26 => Ok(Network::Esmeralda),
            _ => Err(TariError::InvalidNetwork(byte)),
        }
    }

    /// Get the expected Base58 prefix character for this network
    pub fn base58_prefix(&self) -> char {
        match self {
            Network::MainNet => 'T',
            Network::NextNet => 't',
            Network::Esmeralda => 'e',
        }
    }

    /// Get the emoji prefix for this network
    pub fn emoji_prefix(&self) -> &'static str {
        match self {
            Network::MainNet => "🐢",
            Network::NextNet => "⏩",
            Network::Esmeralda => "💎",
        }
    }

    /// Get network name as string
    pub fn name(&self) -> &'static str {
        match self {
            Network::MainNet => "MainNet",
            Network::NextNet => "NextNet", 
            Network::Esmeralda => "Esmeralda",
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Network::MainNet
    }
}

impl FromStr for Network {
    type Err = TariError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        #[allow(clippy::enum_glob_use)]
        use Network::*;
        match value.to_lowercase().as_str() {
            "mainnet" => Ok(MainNet),
            "nextnet" => Ok(NextNet),
            "esmeralda" | "esme" => Ok(Esmeralda),
            invalid => Err(TariError::InvalidNetworkName(invalid.to_string())),
        }
    }
}
impl TryFrom<String> for Network {
    type Error = TariError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::from_str(value.as_str())
    }
}

impl From<Network> for String {
    fn from(n: Network) -> Self {
        n.to_string()
    }
}


impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (0x{:02x})", self.name(), self.as_byte())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_bytes() {
        assert_eq!(Network::MainNet.as_byte(), 0x00);
        assert_eq!(Network::NextNet.as_byte(), 0x02);
        assert_eq!(Network::Esmeralda.as_byte(), 0x26);
    }

    #[test]
    fn test_network_from_byte() {
        assert_eq!(Network::from_byte(0x00).unwrap(), Network::MainNet);
        assert_eq!(Network::from_byte(0x02).unwrap(), Network::NextNet);
        assert_eq!(Network::from_byte(0x26).unwrap(), Network::Esmeralda);
        assert!(Network::from_byte(0xFF).is_err());
    }

    #[test]
    fn test_network_prefixes() {
        assert_eq!(Network::MainNet.base58_prefix(), 'T');
        assert_eq!(Network::NextNet.base58_prefix(), 't');
        assert_eq!(Network::Esmeralda.base58_prefix(), 'e');
    }
} 