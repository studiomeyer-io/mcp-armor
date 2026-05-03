//! Unicode normalization for evasion-resistant scanning. Applies, in order:
//! 1. Strip zero-width characters (U+200B..U+200F, U+FEFF, U+2060)
//! 2. Strip tag-unicode (U+E0000..U+E007F)
//! 3. NFKC normalization (folds fullwidth, ligatures, etc.)
//!
//! Ports the ai-shield Round 4 pattern set into Rust.

use unicode_normalization::UnicodeNormalization;

const ZERO_WIDTH: &[char] = &[
    '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{2060}', '\u{FEFF}',
];

pub fn normalize(input: &str) -> String {
    let stripped: String = input
        .chars()
        .filter(|c| !is_zero_width(*c) && !is_tag_unicode(*c))
        .collect();
    stripped.nfkc().collect()
}

fn is_zero_width(c: char) -> bool {
    ZERO_WIDTH.contains(&c)
}

fn is_tag_unicode(c: char) -> bool {
    matches!(c as u32, 0xE0000..=0xE007F)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width() {
        let with_zw = "ign\u{200b}ore";
        assert_eq!(normalize(with_zw), "ignore");
    }

    #[test]
    fn strips_tag_unicode() {
        let with_tag = "rev\u{e0072}eal";
        assert_eq!(normalize(with_tag), "reveal");
    }

    #[test]
    fn folds_fullwidth() {
        // Fullwidth "sudo" → ascii "sudo"
        let fw = "ｓｕｄｏ";
        assert_eq!(normalize(fw), "sudo");
    }

    #[test]
    fn passthrough_clean_ascii() {
        let s = "hello world";
        assert_eq!(normalize(s), s);
    }
}
