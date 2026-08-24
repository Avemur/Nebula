//! Who a caller is (README.md §13).
//!
//! v1 made the bearer token *be* the tenant id, which meant the tenant was a
//! claim rather than a fact. Every isolation guarantee in §22 is keyed on it —
//! the session scratchpad of §22.5, the replay store of §22.4, the egress
//! allowlist of §22.8, the buckets of §22.7 — so an unverified tenant made all
//! of them "isolated, provided everyone is honest".
//!
//! A signed token closes that without a database: the tenant travels in the
//! token and an HMAC proves the control plane issued it.
//!
//! ```text
//! acme.7b1f…                 <- tenant, then a SHA-256 HMAC of it, hex
//! ```
//!
//! ponytail: no expiry, no revocation list, no refresh. A token is a bearer
//! credential that says one thing — "this is tenant X" — and rotating the
//! secret invalidates every token at once, which is the whole of the revocation
//! story until someone needs finer. Expiry needs a clock in the token and a
//! decision about skew; neither is free, and neither is load-bearing while the
//! secret can be rotated.

use ring::hmac;

/// Bound on a tenant id. It is a map key in four different stores; an unbounded
/// one is a free allocation for anyone asking.
pub const MAX_TENANT_BYTES: usize = 64;

/// The environment variable that turns verification on.
pub const SECRET_ENV: &str = "NEBULA_AUTH_SECRET";

/// How the gateway decides who is calling.
pub enum Auth {
    /// **Development only.** The bearer token is taken as the tenant id, so any
    /// caller can be any tenant.
    ///
    /// Kept as the default because the alternative — refusing every request
    /// until a secret is configured — means `cargo run` does not work, and the
    /// predictable response to that is a secret of `x` that everybody assumes
    /// is security. The binaries announce this mode loudly at startup instead.
    Insecure,
    /// Tokens must carry a valid HMAC over the tenant id.
    Signed(hmac::Key),
}

impl Auth {
    /// Reads [`SECRET_ENV`]. Absent leaves verification off.
    pub fn from_env() -> Self {
        match std::env::var(SECRET_ENV) {
            Ok(secret) if !secret.trim().is_empty() => Self::signed(secret.trim().as_bytes()),
            _ => Self::Insecure,
        }
    }

    pub fn signed(secret: &[u8]) -> Self {
        Self::Signed(hmac::Key::new(hmac::HMAC_SHA256, secret))
    }

    pub fn is_enforcing(&self) -> bool {
        matches!(self, Self::Signed(_))
    }

    /// Issues a token for `tenant`.
    ///
    /// Returns `None` under [`Auth::Insecure`]: minting a token that nothing
    /// verifies would hand someone a credential-shaped string and let them
    /// believe it was one.
    pub fn mint(&self, tenant: &str) -> Option<String> {
        let Self::Signed(key) = self else {
            return None;
        };
        is_valid_tenant(tenant).then(|| {
            let tag = hmac::sign(key, tenant.as_bytes());
            format!("{tenant}.{}", hex(tag.as_ref()))
        })
    }

    /// The tenant this token proves, if any.
    pub fn tenant_of(&self, token: &str) -> Option<String> {
        let token = token.trim();
        match self {
            Self::Insecure => is_valid_tenant(token).then(|| token.to_string()),
            Self::Signed(key) => {
                // `rsplit_once` so a tenant containing a dot could never be
                // spelled to move the boundary — though `is_valid_tenant`
                // already forbids one, and both checks are cheap.
                let (tenant, signature) = token.rsplit_once('.')?;
                if !is_valid_tenant(tenant) {
                    return None;
                }
                // `hmac::verify` is constant-time. Comparing hex strings with
                // `==` would leak the signature one byte at a time to anyone
                // willing to measure, which is the classic way this is got
                // wrong.
                hmac::verify(key, tenant.as_bytes(), &unhex(signature)?)
                    .ok()
                    .map(|()| tenant.to_string())
            }
        }
    }
}

/// Alphanumerics, dash and underscore only.
///
/// The charset is not cosmetic. A tenant id is the first element of the KV key
/// (§22.5), the idempotency slot (§22.4) and the egress lookup (§22.8), and it
/// is the part of the token before the separator — so forbidding `.` is what
/// makes the token split unambiguous.
pub fn is_valid_tenant(tenant: &str) -> bool {
    !tenant.is_empty()
        && tenant.len() <= MAX_TENANT_BYTES
        && tenant
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        Auth::signed(b"a shared secret")
    }

    #[test]
    fn a_minted_token_names_its_tenant_back() {
        let auth = auth();
        let token = auth.mint("acme").expect("mint");
        assert!(token.starts_with("acme."));
        assert_eq!(auth.tenant_of(&token).as_deref(), Some("acme"));
    }

    #[test]
    fn a_token_for_one_tenant_cannot_be_edited_into_another() {
        let auth = auth();
        let token = auth.mint("acme").expect("mint");
        let signature = token.split_once('.').unwrap().1;

        // The whole point. Under v1 auth "globex" *was* a valid token for
        // globex; now the signature is over the tenant, so moving the name
        // invalidates it.
        assert_eq!(auth.tenant_of(&format!("globex.{signature}")), None);
        assert_eq!(auth.tenant_of("globex"), None);
        assert_eq!(auth.tenant_of("globex."), None);
    }

    #[test]
    fn a_token_from_another_secret_is_refused() {
        let token = Auth::signed(b"someone else's secret")
            .mint("acme")
            .expect("mint");
        // Rotating the secret is the entire revocation story (see the module
        // docs), so this is the test that says rotation works.
        assert_eq!(auth().tenant_of(&token), None);
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let auth = auth();
        let token = auth.mint("acme").expect("mint");
        let (tenant, signature) = token.split_once('.').unwrap();

        // Flip one hex digit.
        let mut broken: Vec<char> = signature.chars().collect();
        broken[0] = if broken[0] == 'a' { 'b' } else { 'a' };
        let broken: String = broken.into_iter().collect();
        assert_eq!(auth.tenant_of(&format!("{tenant}.{broken}")), None);

        // Truncated, over-long, and non-hex signatures must all be refused by
        // the decoder rather than reaching the verifier as short input.
        assert_eq!(
            auth.tenant_of(&format!("{tenant}.{}", &signature[..10])),
            None
        );
        assert_eq!(auth.tenant_of(&format!("{tenant}.zzzz")), None);
        assert_eq!(auth.tenant_of(&format!("{tenant}.{signature}ab")), None);
    }

    #[test]
    fn a_tenant_id_cannot_contain_the_separator_or_run_long() {
        let auth = auth();
        assert!(auth.mint("has.a.dot").is_none());
        assert!(auth.mint("has a space").is_none());
        assert!(auth.mint("").is_none());
        assert!(auth.mint(&"t".repeat(MAX_TENANT_BYTES + 1)).is_none());

        assert!(auth.mint("acme-prod_2").is_some());
    }

    #[test]
    fn insecure_mode_takes_the_token_at_its_word_but_will_not_mint() {
        let auth = Auth::Insecure;
        assert!(!auth.is_enforcing());
        assert_eq!(auth.tenant_of("acme").as_deref(), Some("acme"));

        // Still validated as a tenant id — the charset guards four different
        // stores, and that is true whether or not anyone checked a signature.
        assert_eq!(auth.tenant_of("has a space"), None);
        assert_eq!(auth.tenant_of(""), None);

        // Minting under a mode that verifies nothing would hand back a
        // credential-shaped string that is not a credential.
        assert_eq!(auth.mint("acme"), None);
    }

    #[test]
    fn hex_round_trips_and_rejects_what_is_not_hex() {
        assert_eq!(
            unhex(&hex(&[0x00, 0x7f, 0xff])),
            Some(vec![0x00, 0x7f, 0xff])
        );
        assert_eq!(unhex("abc"), None, "odd length");
        assert_eq!(unhex("zz"), None, "not hex");
    }
}
