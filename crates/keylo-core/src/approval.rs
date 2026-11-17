//! A request from an agent (via `keylo mcp`) for secrets its access key doesn't cover. The Keylo
//! app shows it (`keylow --approve <base64 JSON>`), verifies the user, and answers with an exit
//! code. The reason and command come from the agent: untrusted text. The encoding matches the C#
//! build (PascalCase JSON, the operation as a number), so either keylo can open either app.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::access::SecretOperation;

pub const ARGUMENT: &str = "--approve";
pub const DENIED: i32 = 10;
pub const ALLOWED_ONCE: i32 = 11;
/// Allowed, and the secrets were added to the requesting key's scope.
pub const ALLOWED_ALWAYS: i32 = 12;
const MAX_TEXT: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ApprovalRequest {
    /// 0 browse, 1 run, 2 get (as the C# enum).
    pub operation: u8,
    pub secrets: Vec<String>,
    pub key_id: Option<String>,
    pub key_name: Option<String>,
    pub reason: Option<String>,
    pub command: Option<String>,
    pub can_always_allow: bool,
    /// request_access: only offers adding the secrets to the key.
    #[serde(default)]
    pub grant_only: bool,
}

impl ApprovalRequest {
    pub fn op(&self) -> SecretOperation {
        match self.operation {
            0 => SecretOperation::Browse,
            2 => SecretOperation::Get,
            _ => SecretOperation::Run,
        }
    }

    pub fn op_code(op: SecretOperation) -> u8 {
        match op {
            SecretOperation::Browse => 0,
            SecretOperation::Run => 1,
            SecretOperation::Get => 2,
        }
    }

    pub fn encode(&self) -> String {
        let mut clipped = self.clone();
        clipped.reason = clipped.reason.map(|r| clip(&r));
        clipped.command = clipped.command.map(|c| clip(&c));
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&clipped).unwrap())
    }

    pub fn decode(encoded: &str) -> Option<Self> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

fn clip(text: &str) -> String {
    if text.chars().count() > MAX_TEXT {
        text.chars().take(MAX_TEXT).collect::<String>() + "…"
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_csharp_encoding() {
        let json = r#"{"Operation":1,"Secrets":["db"],"KeyId":"ab12cd34","KeyName":"Claude Code","Reason":"migrate","Command":"[bash] x","CanAlwaysAllow":true,"GrantOnly":false}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(json);
        let r = ApprovalRequest::decode(&encoded).unwrap();
        assert_eq!(r.op(), SecretOperation::Run);
        assert_eq!(r.secrets, vec!["db"]);
        assert!(r.can_always_allow && !r.grant_only);
        assert_eq!(ApprovalRequest::decode(&r.encode()).unwrap().key_name.as_deref(), Some("Claude Code"));
    }
}
