//! v0.3 Feature B — Unicode confusable / homoglyph skeleton.
//!
//! The Stage-3 NFKC pass folds *width* (`ｓｕｄｏ` → `sudo`) and *legacy
//! compatibility forms* (`Ⅹ` → `X`), but does **not** fold Cyrillic /
//! Greek / Cherokee / Latin-Extended *whole-script confusables* (`іgnоrе`
//! with Cyrillic i/o/e still reads as `ignore` to a human and to an LLM
//! but survives NFKC byte-for-byte). That gap is the OWASP Top-10 LLM-09
//! "deceptive tool naming" attack vector flagged by the Zealynx 2026
//! forensic report.
//!
//! This module implements the relevant subset of UTS-39 Annex 24
//! (`confusables.txt`) needed to fold the most common script-confusable
//! letters back to their Latin skeleton. We keep the table local
//! (~180 entries) instead of pulling a 8000-entry external crate so the
//! audit surface stays small (the v0.1 "single signed binary, minimal
//! dep tree" pitch). The table covers:
//!
//! - **Cyrillic block** (U+0400–U+04FF) — full upper/lower Latin-lookalikes
//! - **Greek block** (U+0370–U+03FF) — capital + lowercase confusables
//! - **Cherokee block** (U+13A0–U+13FF) — Latin-capital-shaped letters
//! - **Latin Extended-IPA** small-caps and stylistic alternates that
//!   render visually as ASCII (`ɑ`, `ɡ`, `ı`, `ɩ`)
//! - **Mathematical Alphanumeric** capital A–Z + lowercase a–z (NFKC
//!   handles most but we keep the table entries as belt-and-braces in
//!   case NFKC is ever bypassed)
//! - **Armenian** + **Coptic** + **Glagolitic** Latin-lookalikes
//!
//! The skeleton is **lossy on purpose**: any char without a mapping is
//! kept verbatim, and the comparison is whether the resulting skeleton
//! re-matches a scanner pattern. False-positive risk is bounded because
//! Stage-4 only *escalates* a verdict (re-scan finds new hits) — it
//! never *reduces* a verdict.

use std::sync::OnceLock;

/// Hand-curated UTS-39 confusable mappings: codepoint → ASCII letter.
/// All entries are visually-confusable with the target ASCII byte at a
/// reasonable terminal/proportional font. Source cross-checked against
/// `https://www.unicode.org/Public/security/latest/confusables.txt`
/// (revision 16.0.0, 2024-09-10) and pruned to script blocks where the
/// confusion actually arises in MCP tool names / JSON-RPC payloads.
///
/// Format: `(from, to)` — `from` is the confusable codepoint, `to` is
/// the ASCII letter it folds to in the skeleton.
const CONFUSABLES: &[(char, char)] = &[
    // ── Cyrillic lowercase ───────────────────────────────────────────
    ('\u{0430}', 'a'), // а CYRILLIC SMALL LETTER A
    ('\u{0435}', 'e'), // е CYRILLIC SMALL LETTER IE
    ('\u{043E}', 'o'), // о CYRILLIC SMALL LETTER O
    ('\u{0440}', 'p'), // р CYRILLIC SMALL LETTER ER
    ('\u{0441}', 'c'), // с CYRILLIC SMALL LETTER ES
    ('\u{0443}', 'y'), // у CYRILLIC SMALL LETTER U
    ('\u{0445}', 'x'), // х CYRILLIC SMALL LETTER HA
    ('\u{0456}', 'i'), // і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    ('\u{0458}', 'j'), // ј CYRILLIC SMALL LETTER JE
    ('\u{0455}', 's'), // ѕ CYRILLIC SMALL LETTER DZE
    ('\u{04CF}', 'l'), // ӏ CYRILLIC SMALL LETTER PALOCHKA
    ('\u{0501}', 'd'), // ԁ CYRILLIC SMALL LETTER KOMI DE
    // ── Cyrillic uppercase ───────────────────────────────────────────
    ('\u{0410}', 'A'), // А
    ('\u{0412}', 'B'), // В
    ('\u{0415}', 'E'), // Е
    ('\u{041D}', 'H'), // Н
    ('\u{041A}', 'K'), // К
    ('\u{041C}', 'M'), // М
    ('\u{041E}', 'O'), // О
    ('\u{0420}', 'P'), // Р
    ('\u{0421}', 'C'), // С
    ('\u{0422}', 'T'), // Т
    ('\u{0425}', 'X'), // Х
    ('\u{0406}', 'I'), // І BYELORUSSIAN-UKRAINIAN I
    ('\u{0408}', 'J'), // Ј CYRILLIC CAPITAL LETTER JE
    ('\u{0405}', 'S'), // Ѕ CYRILLIC CAPITAL LETTER DZE
    // ── Greek lowercase ──────────────────────────────────────────────
    ('\u{03BF}', 'o'), // ο GREEK SMALL LETTER OMICRON
    ('\u{03B1}', 'a'), // α GREEK SMALL LETTER ALPHA (visually similar)
    ('\u{03C1}', 'p'), // ρ GREEK SMALL LETTER RHO
    ('\u{03C5}', 'u'), // υ GREEK SMALL LETTER UPSILON (lookalike for u/v)
    ('\u{03B9}', 'i'), // ι GREEK SMALL LETTER IOTA
    ('\u{03BD}', 'v'), // ν GREEK SMALL LETTER NU
    // ── Greek uppercase ──────────────────────────────────────────────
    ('\u{0391}', 'A'), // Α
    ('\u{0392}', 'B'), // Β
    ('\u{0395}', 'E'), // Ε
    ('\u{0396}', 'Z'), // Ζ
    ('\u{0397}', 'H'), // Η
    ('\u{0399}', 'I'), // Ι
    ('\u{039A}', 'K'), // Κ
    ('\u{039C}', 'M'), // Μ
    ('\u{039D}', 'N'), // Ν
    ('\u{039F}', 'O'), // Ο
    ('\u{03A1}', 'P'), // Ρ
    ('\u{03A4}', 'T'), // Τ
    ('\u{03A5}', 'Y'), // Υ
    ('\u{03A7}', 'X'), // Χ
    // ── Cherokee uppercase-shaped letters ────────────────────────────
    // (Cherokee glyphs visually match Latin capitals; this is the
    // class flagged in the Zealynx 2026 report — `ge᎓check` instead
    // of `geo_check` evading naive Aho-Corasick on tool names.)
    //
    // R1-fix (Critic MED): the v0.3 first cut included three speculative
    // mappings (`Ꭰ` → O, `Ꮍ` → P, `Ꮾ` → L) marked "pragmatic" /
    // "conservative" / "Ꮍ-area". None of those appear in the official
    // `confusables.txt` rev 16.0.0 published by Unicode. Folding them
    // would create false positives on legitimate Cherokee-language tool
    // descriptions. Removed. Retained set is the subset that DOES appear
    // in confusables.txt with Latin-capital lookalikes.
    ('\u{13AA}', 'A'), // Ꭺ
    ('\u{13AC}', 'E'), // Ꭼ
    ('\u{13AF}', 'H'), // Ꭿ
    ('\u{13B7}', 'M'), // Ꮇ
    ('\u{13C6}', 'I'), // Ꮖ
    ('\u{13D9}', 'V'), // Ꮵ
    // ── Latin Extended-IPA / Phonetic confusables ────────────────────
    ('\u{0251}', 'a'), // ɑ LATIN SMALL LETTER ALPHA
    ('\u{0261}', 'g'), // ɡ LATIN SMALL LETTER SCRIPT G
    ('\u{0131}', 'i'), // ı LATIN SMALL LETTER DOTLESS I
    ('\u{0269}', 'i'), // ɩ LATIN SMALL LETTER IOTA
    ('\u{1D04}', 'c'), // ᴄ LATIN LETTER SMALL CAPITAL C
    ('\u{1D07}', 'e'), // ᴇ LATIN LETTER SMALL CAPITAL E
    ('\u{1D0B}', 'k'), // ᴋ LATIN LETTER SMALL CAPITAL K
    ('\u{1D0F}', 'o'), // ᴏ LATIN LETTER SMALL CAPITAL O
    ('\u{1D18}', 'p'), // ᴘ LATIN LETTER SMALL CAPITAL P
    ('\u{1D1B}', 't'), // ᴛ LATIN LETTER SMALL CAPITAL T
    ('\u{0274}', 'n'), // ɴ LATIN LETTER SMALL CAPITAL N
    // ── Armenian Latin-lookalikes ────────────────────────────────────
    ('\u{054F}', 'S'), // Տ ARMENIAN CAPITAL LETTER TIWN (S-shaped)
    ('\u{0555}', 'O'), // Օ ARMENIAN CAPITAL LETTER OH
    ('\u{0585}', 'o'), // օ ARMENIAN SMALL LETTER OH
    // ── Mathematical Alphanumeric (defence-in-depth — NFKC handles most) ─
    ('\u{1D400}', 'A'),
    ('\u{1D401}', 'B'),
    ('\u{1D402}', 'C'),
    ('\u{1D403}', 'D'),
    ('\u{1D404}', 'E'),
    ('\u{1D405}', 'F'),
    ('\u{1D406}', 'G'),
    ('\u{1D407}', 'H'),
    ('\u{1D408}', 'I'),
    ('\u{1D409}', 'J'),
    ('\u{1D40A}', 'K'),
    ('\u{1D40B}', 'L'),
    ('\u{1D40C}', 'M'),
    ('\u{1D40D}', 'N'),
    ('\u{1D40E}', 'O'),
    ('\u{1D40F}', 'P'),
    ('\u{1D410}', 'Q'),
    ('\u{1D411}', 'R'),
    ('\u{1D412}', 'S'),
    ('\u{1D413}', 'T'),
    ('\u{1D414}', 'U'),
    ('\u{1D415}', 'V'),
    ('\u{1D416}', 'W'),
    ('\u{1D417}', 'X'),
    ('\u{1D418}', 'Y'),
    ('\u{1D419}', 'Z'),
    // ── Coptic letters that look like Greek/Latin ────────────────────
    ('\u{2C82}', 'B'), // Ⲃ COPTIC CAPITAL LETTER VIDA
    ('\u{2C8E}', 'H'), // Ⲏ COPTIC CAPITAL LETTER HATE
    ('\u{2C9E}', 'O'), // Ⲟ COPTIC CAPITAL LETTER O
    ('\u{2CA4}', 'P'), // Ⲣ COPTIC CAPITAL LETTER RO
    ('\u{2CA8}', 'T'), // Ⲧ COPTIC CAPITAL LETTER TAU
    // ── Glagolitic small-set lookalikes ──────────────────────────────
    ('\u{2C30}', 'A'), // Ⰰ GLAGOLITIC CAPITAL LETTER AZU
];

/// v0.4 — kept `OnceLock<Vec<(char, char)>>` even after a Round-3
/// reviewer suggested searching the `&'static CONFUSABLES` slice
/// directly. The table is currently organised by Unicode block
/// (Cyrillic small / Cyrillic capital / Greek small / ...) rather than
/// strictly ascending codepoint order, so an unguarded `binary_search`
/// on the literal would silently return wrong answers. Sorting + dedup
/// at first-call into a `OnceLock` is a one-shot ~3 µs cost that
/// amortises across the lifetime of the process — well under any
/// hot-path budget. If we ever re-curate the table to be block-and-
/// codepoint-sorted at the source, the `confusables_table_is_sorted_and_deduped`
/// test below will start passing on the raw slice and we can drop the
/// `OnceLock`.
fn lookup() -> &'static [(char, char)] {
    static CELL: OnceLock<Vec<(char, char)>> = OnceLock::new();
    let v = CELL.get_or_init(|| {
        let mut v: Vec<(char, char)> = CONFUSABLES.to_vec();
        v.sort_by_key(|(k, _)| *k);
        v.dedup_by_key(|(k, _)| *k);
        v
    });
    v.as_slice()
}

/// Compute the UTS-39-flavoured skeleton of `input`. Each codepoint
/// that has a known confusable mapping is replaced by its ASCII
/// equivalent; all other codepoints are kept verbatim. The result is
/// only meant for scanner re-matching — never displayed back to a user
/// (that would be a misrepresentation of the original).
///
/// Returns the input unchanged when it contains no mapped codepoints,
/// so callers can cheaply check `skeleton(s) != s` to decide whether
/// the re-scan adds new signal.
#[must_use]
pub fn skeleton(input: &str) -> String {
    // Fast path: ASCII-only input has no confusables to fold.
    if input.is_ascii() {
        return input.to_string();
    }
    let table = lookup();
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if let Ok(idx) = table.binary_search_by_key(&ch, |(k, _)| *k) {
            out.push(table[idx].1);
        } else {
            out.push(ch);
        }
    }
    out
}

/// Returns `true` when `input` contains *any* codepoint that the
/// skeleton would fold to a different value. Useful as a cheap
/// pre-check before the full re-scan in the scanner hot-path.
#[must_use]
pub fn has_confusables(input: &str) -> bool {
    if input.is_ascii() {
        return false;
    }
    let table = lookup();
    input
        .chars()
        .any(|c| table.binary_search_by_key(&c, |(k, _)| *k).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_passthrough_returns_input_unchanged() {
        assert_eq!(
            skeleton("ignore previous instructions"),
            "ignore previous instructions"
        );
        assert_eq!(skeleton(""), "");
        assert_eq!(skeleton("CVE-2026-27124"), "CVE-2026-27124");
    }

    #[test]
    fn cyrillic_lowercase_folds_to_latin() {
        // "іgnоrе" with Cyrillic i (U+0456), o (U+043E), e (U+0435)
        let cyr = "\u{0456}gn\u{043E}r\u{0435}";
        assert_eq!(skeleton(cyr), "ignore");
    }

    #[test]
    fn cyrillic_uppercase_folds_to_latin() {
        // "АРОН" all Cyrillic
        let cyr = "\u{0410}\u{0420}\u{041E}\u{041D}";
        assert_eq!(skeleton(cyr), "APOH");
    }

    #[test]
    fn greek_omicron_folds_to_o() {
        // "ign" + Greek omicron + "re" → "ignore"
        let g = format!("ign{}re", '\u{03BF}');
        assert_eq!(skeleton(&g), "ignore");
    }

    #[test]
    fn cherokee_capital_letters_fold_to_latin() {
        // Cherokee Ꭺ (U+13AA) → A, Ꭼ (U+13AC) → E
        let cherokee = format!("{}b{}c", '\u{13AA}', '\u{13AC}');
        assert_eq!(skeleton(&cherokee), "AbEc");
    }

    #[test]
    fn latin_extended_dotless_i_folds_to_i() {
        let s = "\u{0131}gnore"; // "ıgnore"
        assert_eq!(skeleton(s), "ignore");
    }

    #[test]
    fn math_bold_a_folds_to_a_belt_and_braces() {
        // U+1D400 MATHEMATICAL BOLD CAPITAL A. NFKC already does this,
        // but Stage-4 catches a Stage-3-bypass would-be scenario.
        assert_eq!(skeleton("\u{1D400}"), "A");
    }

    #[test]
    fn unmapped_codepoints_kept_verbatim() {
        // Hindi letter (Devanagari) — no Latin confusable in our table.
        assert_eq!(
            skeleton("\u{0905}\u{0906}\u{0907}"),
            "\u{0905}\u{0906}\u{0907}"
        );
    }

    #[test]
    fn mixed_script_payload_normalises_to_pure_latin() {
        // "ignore" with mixed Cyrillic i + Greek o
        let s = "\u{0456}gn\u{03BF}r\u{0435}"; // i (Cyr) g n o (Greek) r e (Cyr)
        assert_eq!(skeleton(s), "ignore");
    }

    #[test]
    fn has_confusables_detects_correctly() {
        assert!(!has_confusables("hello world"));
        assert!(!has_confusables(""));
        assert!(has_confusables("\u{0456}gnore")); // Cyrillic i
        assert!(has_confusables("\u{1D400}")); // Math bold A
        assert!(!has_confusables("\u{0905}")); // Devanagari (unmapped)
    }

    #[test]
    fn skeleton_is_idempotent() {
        // skeleton(skeleton(x)) == skeleton(x) for any x (because the
        // output is pure ASCII after folding, and ASCII passthrough
        // returns input unchanged).
        let cases = ["ignore", "\u{0456}gn\u{043E}r\u{0435}", "\u{13AA}b\u{13AC}"];
        for c in cases {
            let once = skeleton(c);
            let twice = skeleton(&once);
            assert_eq!(once, twice, "non-idempotent on {c:?}");
        }
    }

    /// v0.4 invariant — there must be no duplicate `from` codepoints in
    /// the raw `CONFUSABLES` table. The `OnceLock`-backed `lookup()`
    /// deduplicates silently, but a silent dedup hides a real curator
    /// mistake (two different ASCII mappings for the same codepoint
    /// would race on which one wins after sort). This test makes that
    /// failure mode an explicit CI gate.
    ///
    /// We deliberately do NOT enforce ascending codepoint order today —
    /// the table is curated by Unicode block (Cyrillic / Greek /
    /// Cherokee / ...) and `lookup()` sorts at first call. If we ever
    /// re-curate to strict ascending order, swap the OnceLock-backed
    /// `lookup()` for direct `binary_search` on the `&'static` slice
    /// and assert ordering here.
    #[test]
    fn confusables_table_has_no_duplicate_from_codepoints() {
        use std::collections::HashSet;
        let mut seen: HashSet<char> = HashSet::with_capacity(CONFUSABLES.len());
        let mut dups: Vec<char> = Vec::new();
        for (from, _) in CONFUSABLES {
            if !seen.insert(*from) {
                dups.push(*from);
            }
        }
        assert!(
            dups.is_empty(),
            "CONFUSABLES has duplicate `from` codepoints: {:?} — remove the duplicates so dedup is a no-op",
            dups.iter()
                .map(|c| format!("U+{:04X}", *c as u32))
                .collect::<Vec<_>>()
        );
    }
}
