/// Emoji mapping for byte values 0-255
/// This is the same mapping used in the original JavaScript implementation
const DICT_SIZE: usize = 256; // number of elements in the symbol dictionary

// The emoji table, mapping byte values to emoji characters
pub const EMOJI_MAP: [char; DICT_SIZE] = [
    '🐢', '📟', '🌈', '🌊', '🎯', '🐋', '🌙', '🤔', '🌕', '⭐', '🎋', '🌰', '🌴', '🌵', '🌲', '🌸', '🌹', '🌻', '🌽',
    '🍀', '🍁', '🍄', '🥑', '🍆', '🍇', '🍈', '🍉', '🍊', '🍋', '🍌', '🍍', '🍎', '🍐', '🍑', '🍒', '🍓', '🍔', '🍕',
    '🍗', '🍚', '🍞', '🍟', '🥝', '🍣', '🍦', '🍩', '🍪', '🍫', '🍬', '🍭', '🍯', '🥐', '🍳', '🥄', '🍵', '🍶', '🍷',
    '🍸', '🍾', '🍺', '🍼', '🎀', '🎁', '🎂', '🎃', '🤖', '🎈', '🎉', '🎒', '🎓', '🎠', '🎡', '🎢', '🎣', '🎤', '🎥',
    '🎧', '🎨', '🎩', '🎪', '🎬', '🎭', '🎮', '🎰', '🎱', '🎲', '🎳', '🎵', '🎷', '🎸', '🎹', '🎺', '🎻', '🎼', '🎽',
    '🎾', '🎿', '🏀', '🏁', '🏆', '🏈', '⚽', '🏠', '🏥', '🏦', '🏭', '🏰', '🐀', '🐉', '🐊', '🐌', '🐍', '🦁', '🐐',
    '🐑', '🐔', '🙈', '🐗', '🐘', '🐙', '🐚', '🐛', '🐜', '🐝', '🐞', '🦋', '🐣', '🐨', '🦀', '🐪', '🐬', '🐭', '🐮',
    '🐯', '🐰', '🦆', '🦂', '🐴', '🐵', '🐶', '🐷', '🐸', '🐺', '🐻', '🐼', '🐽', '🐾', '👀', '👅', '👑', '👒', '🧢',
    '💅', '👕', '👖', '👗', '👘', '👙', '💃', '👛', '👞', '👟', '👠', '🥊', '👢', '👣', '🤡', '👻', '👽', '👾', '🤠',
    '👃', '💄', '💈', '💉', '💊', '💋', '👂', '💍', '💎', '💐', '💔', '🔒', '🧩', '💡', '💣', '💤', '💦', '💨', '💩',
    '➕', '💯', '💰', '💳', '💵', '💺', '💻', '💼', '📈', '📜', '📌', '📎', '📖', '📿', '📡', '⏰', '📱', '📷', '🔋',
    '🔌', '🚰', '🔑', '🔔', '🔥', '🔦', '🔧', '🔨', '🔩', '🔪', '🔫', '🔬', '🔭', '🔮', '🔱', '🗽', '😂', '😇', '😈',
    '🤑', '😍', '😎', '😱', '😷', '🤢', '👍', '👶', '🚀', '🚁', '🚂', '🚚', '🚑', '🚒', '🚓', '🛵', '🚗', '🚜', '🚢',
    '🚦', '🚧', '🚨', '🚪', '🚫', '🚲', '🚽', '🚿', '🧲',
];

// Create a reverse lookup map for emoji to byte value
lazy_static::lazy_static! {
    static ref REVERSE_EMOJI: std::collections::HashMap<char, u8> = {
        let mut map = std::collections::HashMap::with_capacity(DICT_SIZE);
        for (i, &emoji) in EMOJI_MAP.iter().enumerate() {
            map.insert(emoji, i as u8);
        }
        map
    };
}

/// Convert bytes to emoji representation
pub fn bytes_to_emoji(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| EMOJI_MAP[b as usize]).collect()
}

/// Convert emoji string back to bytes
pub fn emoji_to_bytes(emoji_str: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(emoji_str.chars().count());
    for c in emoji_str.chars() {
        if let Some(&byte) = REVERSE_EMOJI.get(&c) {
            bytes.push(byte);
        } else {
            return None; // Invalid emoji found
        }
    }
    Some(bytes)
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emoji_map_length() {
        assert_eq!(EMOJI_MAP.len(), 256);
    }

    #[test]
    fn test_bytes_to_emoji() {
        let bytes = vec![0, 1, 2, 255];
        let emoji = bytes_to_emoji(&bytes);
        assert_eq!(emoji, "🐢📟🌈🧲");
    }

    #[test]
    fn test_emoji_to_bytes() {
        let emoji = "🐢📟🌈🧲";
        let bytes = emoji_to_bytes(emoji).unwrap();
        assert_eq!(bytes, vec![0, 1, 2, 255]);
    }

    #[test]
    fn test_roundtrip() {
        let original_bytes = vec![0, 10, 20, 30, 40, 50, 255];
        let emoji = bytes_to_emoji(&original_bytes);
        let recovered_bytes = emoji_to_bytes(&emoji).unwrap();
        assert_eq!(original_bytes, recovered_bytes);
    }
} 