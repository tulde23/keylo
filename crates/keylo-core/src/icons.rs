//! Uploaded icon images, stored as icons/{hash}.png (a 128×128 PNG, made by the app). A secret,
//! category or type refers to one by the icon name "img" + hash, which stays a plain alphanumeric
//! icon name in the OS store. Same files and names as the C# build.

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::{bail, paths, Result};

const PREFIX: &str = "img";
/// Images are 128×128 PNGs; anything much larger isn't one of ours.
const MAX_BYTES: usize = 512 * 1024;
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

pub fn is_image(icon: &str) -> bool {
    icon.len() == PREFIX.len() + 32 && icon.starts_with(PREFIX) && icon[PREFIX.len()..].chars().all(|c| c.is_ascii_hexdigit())
}

fn path_of(icon: &str) -> PathBuf {
    paths::icon_dir().join(format!("{}.png", &icon[PREFIX.len()..]))
}

/// Stores a PNG; returns its icon name. The same image always gets the same name.
pub fn save_png(png: &[u8]) -> Result<String> {
    if !png.starts_with(PNG_MAGIC) {
        bail!("That isn't a PNG image.");
    }
    if png.len() > MAX_BYTES {
        bail!("That image is too large ({} KB; the most is {} KB).", png.len() / 1024, MAX_BYTES / 1024);
    }
    let hash: String = hex::encode(Sha256::digest(png))[..32].to_string();
    let name = format!("{PREFIX}{hash}");
    let path = path_of(&name);
    if !path.exists() {
        fs::create_dir_all(paths::icon_dir())?;
        let temp = path.with_extension("png.tmp");
        fs::write(&temp, png)?;
        fs::rename(&temp, &path)?;
    }
    Ok(name)
}

/// The stored PNG for an "img…" icon name, or None (not an image name, or the file is gone).
pub fn load(icon: &str) -> Option<Vec<u8>> {
    if !is_image(icon) {
        return None;
    }
    fs::read(path_of(icon)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_img_plus_32_hex() {
        assert!(is_image("img0123456789abcdef0123456789abcdef"));
        assert!(!is_image("Key24"));
        assert!(!is_image("img0123"));
        assert!(!is_image("imgzz23456789abcdef0123456789abcdef"));
    }

    #[test]
    fn only_pngs_are_stored() {
        assert!(save_png(b"GIF89a....").is_err());
    }
}
