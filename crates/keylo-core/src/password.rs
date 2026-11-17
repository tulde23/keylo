//! Random passwords with at least one character from each enabled set. Look-alike characters
//! (l, I, O, 0, 1) are left out so values survive being read aloud or retyped.

use rand::seq::SliceRandom;
use rand::Rng;

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
}
