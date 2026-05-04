//! Unicode normalization for evasion-resistant scanning. Applies, in order:
//! 1. Strip zero-width and invisible characters
//!    - U+200B..U+200F (zero-width space/joiner family + LTR/RTL marks)
//!    - U+2060..U+2064 (word joiner + invisible math operators)
//!    - U+FEFF        (BOM / zero-width no-break space)
//! 2. Strip Bidi-formatting characters (U+202A..U+202E, U+2066..U+2069).
//!    Attackers use these to flip the visible vs. logical character order
//!    so a payload looks innocuous to a human reviewer but parses as a
//!    shell call to a naive scanner. v0.1.1 hardening (S991 cold review).
//! 3. Strip tag-unicode (U+E0000..U+E007F)
//! 4. NFKC normalization (folds fullwidth, ligatures, etc.)
//!
//! Ports the ai-shield Round 4 pattern set into Rust, plus the additional
//! Bidi + invisible-math coverage from the cold cross-review (Critic F3).

use unicode_normalization::UnicodeNormalization;

/// Zero-width and invisible characters that must be stripped before
/// pattern matching. Includes the original 7 (ai-shield Round 4) plus
/// U+2061..U+2064 (invisible math operators) added in v0.1.1.
const ZERO_WIDTH: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{200E}', // LEFT-TO-RIGHT MARK
    '\u{200F}', // RIGHT-TO-LEFT MARK
    '\u{2060}', // WORD JOINER
    '\u{2061}', // FUNCTION APPLICATION (invisible math)
    '\u{2062}', // INVISIBLE TIMES
    '\u{2063}', // INVISIBLE SEPARATOR
    '\u{2064}', // INVISIBLE PLUS
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE / BOM
];

/// Bidirectional formatting characters. `rm \u{202E}foo.txt` reads as
/// `rm txt.oof` on screen but executes `rm foo.txt`. Strip them so the
/// visible-vs-logical mismatch cannot bypass downstream pattern matchers.
const BIDI_FORMATTING: &[char] = &[
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
    '\u{2066}', // LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FIRST STRONG ISOLATE
    '\u{2069}', // POP DIRECTIONAL ISOLATE
];

pub fn normalize(input: &str) -> String {
    let stripped: String = input
        .chars()
        .filter(|c| !is_zero_width(*c) && !is_bidi_formatting(*c) && !is_tag_unicode(*c))
        .collect();
    stripped.nfkc().collect()
}

fn is_zero_width(c: char) -> bool {
    ZERO_WIDTH.contains(&c)
}

fn is_bidi_formatting(c: char) -> bool {
    BIDI_FORMATTING.contains(&c)
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

    /// v0.1.1 F3 hardening — invisible math operators must be stripped.
    /// Without this, an attacker could split keywords with U+2062 and
    /// bypass the regex stage entirely.
    #[test]
    fn strips_invisible_math_operators() {
        for sep in ['\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}'] {
            let s = format!("ru{sep}m");
            assert_eq!(normalize(&s), "rum", "failed to strip {sep:?}");
        }
    }

    /// v0.1.1 F3 hardening — RIGHT-TO-LEFT OVERRIDE is the classic
    /// Bidi-spoofing trick used in CVE filename attacks (the Trojan-Source
    /// paper). The scanner must see the logical byte order.
    #[test]
    fn strips_bidi_override() {
        let s = "rm \u{202E}txt.foo";
        assert_eq!(normalize(s), "rm txt.foo");
    }

    /// v0.1.1 F3 hardening — every Bidi formatting code point we strip
    /// must round-trip to clean ASCII.
    #[test]
    fn strips_all_bidi_formatting() {
        for sep in [
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}',
        ] {
            let s = format!("ru{sep}m");
            assert_eq!(normalize(&s), "rum", "failed to strip Bidi {sep:?}");
        }
    }

    /// Defense-in-depth combination: a payload using zero-width + Bidi +
    /// fullwidth simultaneously must still normalize to "sudo".
    #[test]
    fn strips_combined_evasion() {
        let combined = "ｓ\u{200B}ｕ\u{202E}ｄ\u{2062}ｏ";
        assert_eq!(normalize(combined), "sudo");
    }
}
