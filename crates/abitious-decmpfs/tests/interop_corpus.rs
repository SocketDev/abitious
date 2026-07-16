//! Frozen interop corpus — the pressed-data section format is a compatibility
//! contract, so a set of pre-generated hybrid sections (`tests/corpus/vectors.txt`)
//! must keep decoding to their exact original addon bytes FOREVER. A change that
//! breaks decoding an existing hybrid fails here. Regenerate the vectors ONLY on a
//! deliberate, versioned format bump (`cargo run --example gen_corpus`).
//!
//! Each line is `name|raw_hex|section_hex`: the section is what a producer emits
//! into a `PRESSED_DATA` section; the raw is the addon it must decode back to.

use abitious_decmpfs::decode_pressed_data;

/// The committed corpus, baked in at compile time so the test needs no runtime CWD.
const CORPUS: &str = include_str!("corpus/vectors.txt");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn frozen_corpus_still_decodes() {
    let mut count = 0;
    for line in CORPUS.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.split('|');
        let name = parts.next().expect("vector name");
        let raw = unhex(parts.next().expect("raw hex"));
        let section = unhex(parts.next().expect("section hex"));
        assert!(
            parts.next().is_none(),
            "vector {name}: unexpected extra field"
        );
        assert_eq!(
            decode_pressed_data(&section).as_deref(),
            Some(raw.as_slice()),
            "frozen corpus vector {name} no longer decodes — the pressed-data format ABI \
             changed. This is a compatibility break; do not regenerate the corpus to make \
             it pass unless the bump is deliberate + versioned."
        );
        count += 1;
    }
    assert!(
        count >= 3,
        "expected the committed corpus vectors (>= 3), found {count} — is \
         tests/corpus/vectors.txt intact?"
    );
}
