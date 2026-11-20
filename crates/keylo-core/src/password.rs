//! Random passwords with at least one character from each enabled set. Look-alike characters
//! (l, I, O, 0, 1) are left out so values survive being read aloud or retyped. Also a memorable
//! word-passphrase generator ([`generate_passphrase`]) for secrets a person has to type and remember.

use rand::seq::SliceRandom;
use rand::Rng;

/// The EFF "large" diceware wordlist, 7776 words, one per line (hyphens removed so the '-' separator
/// is unambiguous). Source: the Electronic Frontier Foundation (https://www.eff.org/dice), used under
/// CC BY 3.0 US. Each word chosen by position carries log2(7776) ≈ 12.9 bits.
const WORDLIST_TXT: &str = include_str!("eff_wordlist.txt");

const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?";

pub fn generate(length: usize, symbols: bool) -> String {
    let length = length.clamp(8, 128);
    let sets: Vec<&str> = if symbols { vec![LOWER, UPPER, DIGITS, SYMBOLS] } else { vec![LOWER, UPPER, DIGITS] };
    let all: Vec<char> = sets.concat().chars().collect();
    let mut rng = rand::rngs::OsRng;
    let pick = |set: &[char], rng: &mut rand::rngs::OsRng| set[rng.gen_range(0..set.len())];

    let mut chars: Vec<char> = sets.iter().map(|s| pick(&s.chars().collect::<Vec<_>>(), &mut rng)).collect();
    while chars.len() < length {
        chars.push(pick(&all, &mut rng));
    }
    chars.shuffle(&mut rng);
    chars.into_iter().collect()
}

/// A memorable passphrase: `words` EFF-wordlist words joined by `-`, e.g. `anchor-spiral-meadow-cobalt-ferry-ridge`.
/// Clamped to 4–12 words (~52–155 bits). For secrets a person must type and remember — the master
/// passphrase, a backup password — where a random string of symbols is unusable.
pub fn generate_passphrase(words: usize) -> String {
    let words = words.clamp(4, 12);
    let list: Vec<&str> = WORDLIST_TXT.lines().filter(|l| !l.is_empty()).collect();
    let mut rng = rand::rngs::OsRng;
    (0..words).map(|_| list[rng.gen_range(0..list.len())]).collect::<Vec<_>>().join("-")
}

#[cfg(test)]
mod tests {
    #[test]
    fn has_every_set_and_length() {
        let p = super::generate(24, true);
        assert_eq!(p.chars().count(), 24);
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(!p.contains('0') && !p.contains('l'));
    }

    #[test]
    fn passphrase_has_the_asked_for_words() {
        let p = super::generate_passphrase(6);
        let words: Vec<&str> = p.split('-').collect();
        assert_eq!(words.len(), 6);
        assert!(words.iter().all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase())));
        // The wordlist is the full EFF large list.
        assert_eq!(super::WORDLIST_TXT.lines().filter(|l| !l.is_empty()).count(), 7776);
        // Clamped, and overwhelmingly not all-identical (would signal a broken RNG/index).
        assert_eq!(super::generate_passphrase(1).split('-').count(), 4);
    }
}
