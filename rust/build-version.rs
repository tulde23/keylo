// Shared by the build scripts of keylo (CLI) and keylow (app): stamps the build date and git
// commit, which keylo_core::build_version!() shows as "1.2.0 · built 2026-11-16 · 8be7492".
// KEYLO_BUILD_DATE (yyyymmdd) and KEYLO_COMMIT override them (e.g. a build from a copy without .git).

fn stamp_version() {
    let date = std::env::var("KEYLO_BUILD_DATE").ok().filter(|d| !d.is_empty()).unwrap_or_else(today);
    let commit = std::env::var("KEYLO_COMMIT").ok().filter(|c| !c.is_empty()).unwrap_or_else(|| {
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        };
        match git(&["rev-parse", "--short=7", "HEAD"]) {
            Some(c) if git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty()) => format!("{c}-dirty"),
            Some(c) => c,
            None => "nogit".into(),
        }
    });
    println!("cargo:rustc-env=KEYLO_BUILD_DATE={date}");
    println!("cargo:rustc-env=KEYLO_COMMIT={commit}");
}

/// Today (UTC) as yyyymmdd, without a date library: days since 1970 to a civil date.
fn today() -> String {
    let days = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() / 86_400).unwrap_or(0) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}")
}
