//! The build's version: "1.2.0 · built 2026-11-16 · ea879d0". Build scripts set KEYLO_BUILD_DATE
//! (yyyymmdd) and KEYLO_COMMIT at compile time; plain cargo builds show the version alone.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn describe(build_date: Option<&str>, commit: Option<&str>) -> String {
    let mut s = VERSION.to_string();
    if let Some(d) = build_date.filter(|d| d.len() == 8 && d.chars().all(|c| c.is_ascii_digit())) {
        s += &format!(" · built {}-{}-{}", &d[..4], &d[4..6], &d[6..]);
    }
    if let Some(c) = commit.filter(|c| !c.is_empty()) {
        s += &format!(" · {c}");
    }
    s
}

/// This build's description, from the values baked in at compile time.
#[macro_export]
macro_rules! build_version {
    () => {
        $crate::version::describe(option_env!("KEYLO_BUILD_DATE"), option_env!("KEYLO_COMMIT"))
    };
}
