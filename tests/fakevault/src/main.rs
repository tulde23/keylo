// Stands in for `op`, `aws` and `claude` in tests (it acts as whichever its file name says), with made-up data.
// Build: cargo build --release --manifest-path tests/fakevault/Cargo.toml, then copy
// tests/fakevault/target/release/fakevault.exe to op.exe, aws.exe and claude.exe in a folder of their own.
use std::io::{Read, Write};

fn log(line: &str) {
    if let Ok(p) = std::env::var("FAKE_LOG") {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p).unwrap();
        writeln!(f, "{line}").unwrap();
    }
}

fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn main() {
    let exe = std::env::current_exe().unwrap();
    let me = exe.file_stem().unwrap().to_string_lossy().to_lowercase();
    let args: Vec<String> = std::env::args().skip(1).collect();
    log(&format!("{me} {}", args.join(" ")));
    let has = |s: &str| args.iter().any(|a| a == s);

    if me == "claude" {
        // Records `claude mcp add/remove` (the key is a throwaway test key).
        return;
    }

    if me == "op" {
        let out = match (args.first().map(String::as_str), args.get(1).map(String::as_str)) {
            (Some("account"), Some("list")) => r#"[{"url":"my.1password.com"},{"url":"acme.1password.com"}]"#.to_string(),
            (Some("item"), Some("list")) if has("--tags") => "[]".to_string(),
            (Some("item"), Some("list")) => {
                if arg_after(&args, "--account") == Some("my.1password.com") {
                    r#"[{"id":"gh1","title":"GitHub","vault":{"id":"v1","name":"Private"},"category":"LOGIN"},{"id":"st1","title":"Stripe","vault":{"id":"v1","name":"Private"},"category":"API_CREDENTIAL"}]"#.to_string()
                } else {
                    r#"[{"id":"gh2","title":"GitHub","vault":{"id":"v9","name":"Shared"},"category":"LOGIN"}]"#.to_string()
                }
            }
            (Some("item"), Some("get")) => {
                let reveal = has("--reveal");
                let v = |s: &str| if reveal { format!(r#","value":"{s}""#) } else { String::new() };
                format!(
                    r#"{{"id":"gh1","title":"GitHub","fields":[{{"purpose":"USERNAME","label":"username"{}}},{{"purpose":"PASSWORD","label":"password","type":"CONCEALED"{}}},{{"label":"API token","type":"CONCEALED"{}}}],"urls":[{{"href":"https://github.com","primary":true}}]}}"#,
                    v("octocat"), v("fake-gh-password-123"), v("fake-gh-token-456")
                )
            }
            (Some("vault"), Some("get")) => r#"{"id":"v1","name":"Private"}"#.to_string(),
            (Some("item"), Some("create")) => {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s).unwrap();
                log(&format!("op stdin: {s}"));
                r#"{"id":"new1"}"#.to_string()
            }
            _ => {
                eprintln!("[ERROR] unknown command");
                std::process::exit(1);
            }
        };
        println!("{out}");
        return;
    }

    // aws secretsmanager <command>
    if args.first().map(String::as_str) != Some("secretsmanager") {
        std::process::exit(2);
    }
    if arg_after(&args, "--profile") == Some("expired") {
        eprintln!("\nAn error occurred (ExpiredTokenException) when calling the ListSecrets operation: The security token included in the request is expired");
        std::process::exit(254);
    }
    let out = match args.get(1).map(String::as_str) {
        Some("list-secrets") => r#"{"SecretList":[{"ARN":"arn:aws:sm:dev:orders-db","Name":"orders/db","Description":"Orders database"},{"ARN":"arn:aws:sm:dev:web","Name":"web/api-key"}]}"#.to_string(),
        Some("get-secret-value") => {
            let id = arg_after(&args, "--secret-id").unwrap_or("");
            match (arg_after(&args, "--profile"), id) {
                (_, "orders/db-prod") => r#"{"SecretString":"{\"username\":\"orders_prod\",\"password\":\"fake-prod-pw\",\"host\":\"prod.db\"}"}"#.to_string(),
                (Some("uat-p"), _) => r#"{"SecretString":"{\"username\":\"orders_uat\",\"password\":\"fake-uat-pw\",\"host\":\"uat.db\"}"}"#.to_string(),
                _ => r#"{"SecretString":"{\"username\":\"orders_dev\",\"password\":\"fake-dev-pw\",\"host\":\"dev.db\"}"}"#.to_string(),
            }
        }
        Some("describe-secret") => {
            eprintln!("\nAn error occurred (ResourceNotFoundException) when calling the DescribeSecret operation: Secrets Manager can't find the specified secret.");
            std::process::exit(254);
        }
        Some("create-secret") => {
            let file = arg_after(&args, "--secret-string").unwrap_or("").trim_start_matches("file://");
            log(&format!("aws value file: {}", std::fs::read_to_string(file).unwrap_or_default()));
            r#"{"ARN":"arn:new","Name":"keylo/x"}"#.to_string()
        }
        _ => {
            eprintln!("unknown");
            std::process::exit(2);
        }
    };
    println!("{out}");
}
