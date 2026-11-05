//! API-key and token recogniser: each key is masked whole, prefix included.
//!
//! A key's prefix (`sk-`, `ghp_`, `AKIA`, `eyJ`) is part of the secret. A
//! detector that finds only the tail masks a fragment, leaves the prefix in
//! clear, and lets the tail match another rule: security-review B found an IBAN on the
//! tail of an `sk-proj-` key. So each shape below matches the whole key, and
//! the registry ranks a secret with the top label, so no IBAN, card or phone
//! shape relabels it.
//!
//! The shapes follow the issuers' documented formats. A minimum length keeps
//! `sk-learn` and other short words in clear. No word boundary is required: a
//! key glued to Han text, `_` or `-` is still a key. A key that a line break
//! wraps is joined across its continuation lines, bounded by
//! [`MAX_WRAP_BYTES`], so the scan stays linear. The
//! recogniser never logs a value.

use std::sync::LazyLock;

use regex::Regex;

use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

use self::formats::{
    is_value_char, secret_values, shape_values, AUTHORIZATION_RE, AWS_PAIR_RE, DSN_NO_SCHEME_RE,
    DSN_USERINFO_RE, HEADERLESS_PEM_RE, PEM_BLOCK_RE, PUTTY_KEY_RE, VALUE_SHAPES_RE,
};
use self::glued::{glued_keys, known_glued_format};
use self::key_names::AWS_SECRET_RE;
use self::key_view::{
    is_dotted_key_char, is_key_char, join_wrapped, lower_aws_keys, unescaped_keys, KeyView,
};

/// Score of a key. A key's shape is certain, so it sits above every floor.
pub const SCORE: f32 = 1.0;

/// The name echoed in [`Span::recognizer`].
const NAME: &str = "secrets";

/// Bytes a key may grow by joining its continuation lines. A provider key wraps
/// over a few lines; 8 KB is far past any real key, and it keeps the join bounded.
pub const MAX_WRAP_BYTES: usize = 8192;

/// The issuer key shapes: the prefix and the key alphabet after it, with the
/// shortest whole key (prefix included) each shape accepts.
const SHAPES: &[(&str, usize)] = &[
    // OpenAI and Anthropic keys: `sk-`, `sk-proj-`, `sk-ant-…`.
    // `sk-` must not follow a letter or digit (risk-…, task-…). The boundary is a
    // character outside the span, and the span is group 1.
    (r"(?:^|[^A-Za-z0-9])(sk-[A-Za-z0-9_\-]*)", 20),
    // Dropbox short-lived access tokens: `sl.`, same boundary rule as `sk-`.
    // `sl.u.` is the current layout.
    (r"(?:^|[^A-Za-z0-9])(sl\.(?:[a-z]\.)?[A-Za-z0-9_\-]*)", 24),
    // GitHub classic and OAuth tokens, and fine-grained personal tokens.
    (r"gh[pousr]_[A-Za-z0-9]*", 40),
    (r"github_pat_[A-Za-z0-9_]*", 33),
    // Slack bot, user, app and refresh tokens.
    (r"xox[abposr]-[A-Za-z0-9\-]*", 14),
    // Stripe secret, restricted and publishable keys, and webhook secrets.
    (r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]*", 16),
    (r"whsec_[A-Za-z0-9]*", 16),
    // Hugging Face and Groq tokens, GitLab personal tokens, Slack app-level
    // tokens, and the ya29. Google OAuth access token (after `Bearer `).
    (r"hf_[A-Za-z0-9]*", 33),
    (r"gsk_[A-Za-z0-9]*", 33),
    (r"glpat-[A-Za-z0-9_\-]*", 26),
    (r"xapp-[A-Za-z0-9\-]*", 14),
    (r"ya29\.[A-Za-z0-9_\-]*", 25),
    // A ya29. token with more dots inside, such as the `ya29.c.`
    // service-account token, is read whole (the shape above stops at the dot).
    (r"ya29\.[A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]+)+", 25),
    // Package registries and hosting: npm, PyPI, SendGrid, DigitalOcean, Replicate,
    // Telegram bot tokens, Linear, Shopify, Shopify Storefront-free sbp_, Notion.
    (r"npm_[A-Za-z0-9]*", 40),
    (r"pypi-[A-Za-z0-9_\-]*", 50),
    (r"SG\.[A-Za-z0-9_\-.]*", 40),
    (r"dop_v1_[a-f0-9]*", 71),
    (r"r8_[A-Za-z0-9]*", 40),
    (r"[0-9]{8,10}:AA[A-Za-z0-9_\-]*", 44),
    (r"lin_api_[A-Za-z0-9]*", 40),
    (r"shpat_[a-f0-9]*", 38),
    (r"sbp_[a-f0-9]*", 44),
    (r"ntn_[A-Za-z0-9]*", 40),
    // Twilio API key SIDs (SK and 32 hex digits).
    (r"SK[0-9a-f]{32,}", 34),
    // age encryption secret keys.
    (r"AGE-SECRET-KEY-1[A-Z0-9]*", 40),
    // Google OAuth client secrets and refresh tokens, Meta access tokens, and Zoho
    // OAuth tokens (1000.x.y, one token).
    (r"GOCSPX-[A-Za-z0-9_\-]*", 28),
    (r"1//0[A-Za-z0-9_\-]*", 30),
    (r"EAA[A-Za-z0-9]*", 50),
    (r"1000\.[A-Za-z0-9]{8,}\.[A-Za-z0-9]{8,}", 20),
    // xAI, Perplexity, HashiCorp Vault, mesh VPN clients, Grafana, Sentry, Atlassian,
    // Supabase, Shopify, GitLab and Discord bot tokens.
    (r"xai-[A-Za-z0-9]*", 40),
    (r"pplx-[A-Za-z0-9]*", 40),
    (r"hvs\.[A-Za-z0-9_\-]*", 30),
    (r"tskey-[A-Za-z0-9_\-]*", 30),
    (r"glsa_[A-Za-z0-9_]*", 40),
    (r"sntrys_[A-Za-z0-9+/=_\-]*", 40),
    (r"ATATT3x[A-Za-z0-9_\-=]*", 40),
    (r"sb_secret_[A-Za-z0-9_\-]*", 30),
    (r"shpss_[a-f0-9]*", 37),
    (r"shpca_[a-f0-9]*", 38),
    (r"glptt-[a-f0-9]*", 46),
    // GitLab deploy tokens: `gldt-` plus 20 characters.
    (r"gldt-[A-Za-z0-9_\-]*", 25),
    // A Discord bot token: the first field is a user ID in base64, which starts
    // with M, N or O (IDs from 8 or 9 encode to OD or OT), then the timestamp and
    // the signature.
    (
        r"[MNO][A-Za-z0-9_\-]{23,28}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}",
        50,
    ),
    // AWS access key IDs (long-term and temporary).
    (r"(?:AKIA|ASIA)[0-9A-Z]*", 20),
    // Google API keys.
    (r"AIza[0-9A-Za-z_\-]*", 39),
    // JSON Web Tokens: a base64url header and payload, then an optional signature.
    (r"eyJ[A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]*)*", 12),
    // New Relic user keys, Docker personal tokens, GitLab runner tokens, the Mailgun
    // private key, and DigitalOcean OAuth tokens.
    (r"NRAK-[A-Za-z0-9]*", 32),
    (r"dckr_pat_[A-Za-z0-9_\-]*", 30),
    (r"glrt-[A-Za-z0-9_\-]*", 20),
    (r"key-[A-Za-z0-9]*", 36),
    (r"doo_v1_[a-f0-9]*", 64),
    // AI and data tools: LangSmith, Pinecone, Hugging Face org, Databricks, Airtable,
    // the legacy Notion integration secret.
    (r"lsv2_(?:pt|sk)_[A-Za-z0-9_]*", 40),
    (r"pcsk_[A-Za-z0-9_]*", 40),
    (r"api_org_[A-Za-z0-9]*", 40),
    (r"dapi[a-f0-9]*", 36),
    (r"pat[A-Za-z0-9]{14}\.[a-f0-9]{64}", 82),
    (r"secret_[A-Za-z0-9]*", 50),
    // Design, API and content tools: Figma, Postman, Contentful, Brevo.
    (r"figd_[A-Za-z0-9_\-]*", 40),
    (r"PMAK-[A-Za-z0-9\-]*", 40),
    (r"CFPAT-[A-Za-z0-9_\-]*", 40),
    (r"x(?:keysib|smtpsib)-[A-Za-z0-9\-]*", 40),
    // Hosting, CI and secret stores: Terraform Cloud, Doppler, Pulumi, Netlify,
    // Render, Sentry user tokens, SonarQube, Bitbucket, CircleCI, Buildkite,
    // Dynatrace, Vault batch and recovery tokens, GitLab CI/OAuth/feed/runner
    // tokens.
    (r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]*", 50),
    (r"dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]*", 40),
    (r"pul-[a-f0-9]*", 44),
    (r"nfp_[A-Za-z0-9]*", 40),
    (r"rnd_[A-Za-z0-9]*", 32),
    (r"sntryu_[a-f0-9]*", 40),
    (r"sq[upa]_[a-f0-9]*", 44),
    (
        r"(?:^|[^A-Za-z0-9])(ATBB[A-Z0-9]*[a-z][A-Za-z0-9_=.\-]*)",
        32,
    ),
    (r"CCIPAT_[A-Za-z0-9_]*", 40),
    (r"bkua_[a-f0-9]*", 45),
    (r"dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]*", 50),
    (r"hv[br]\.[A-Za-z0-9_\-]*", 30),
    (r"gl(?:cbt|oas|ft|imt|soat|agent|ffct)-[A-Za-z0-9_\-]*", 25),
    (r"GR1348941[A-Za-z0-9_\-]*", 29),
    // Slack refresh and client tokens.
    (r"xox[ce]-[A-Za-z0-9\-]*", 20),
    // Payments: Mailchimp (`-us` and the data-centre number), Braintree, Square,
    // Plaid, Shopify private apps.
    (r"(?:^|[^A-Za-z0-9])([a-f0-9]{32}-us[0-9]{1,2})", 36),
    (
        r"access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}",
        40,
    ),
    (r"sq0(?:atp|csp)-[A-Za-z0-9_\-]*", 29),
    (
        r"access-(?:production|sandbox|development)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        40,
    ),
    (r"shppa_[a-f0-9]*", 38),
    // Clouds: Alibaba and Tencent access key IDs (mixed case, so an upper-case
    // OCR or MRZ run is none), Azure AD client secrets.
    (r"(?:^|[^A-Za-z0-9])(LTAI[A-Z0-9]*[a-z][A-Za-z0-9]*)", 20),
    (r"(?:^|[^A-Za-z0-9])(AKID[A-Z0-9]*[a-z][A-Za-z0-9]*)", 36),
    (
        r"(?:^|[^A-Za-z0-9_~.\-])([A-Za-z0-9_~.]{3}[0-9]Q~[A-Za-z0-9_~.\-]{31,34})",
        40,
    ),
    // Package registries: RubyGems, NuGet, Artifactory.
    (r"rubygems_[a-f0-9]*", 57),
    (r"oy2[a-z0-9]*", 46),
    (r"AKCp[A-Za-z0-9]*", 69),
    // BIP32 extended private keys (base58).
    (r"[xyzt]prv[1-9A-HJ-NP-Za-km-z]*", 100),
];

static SHAPES_RE: LazyLock<Vec<(Regex, usize)>> = LazyLock::new(|| {
    SHAPES
        .iter()
        .map(|(shape, min_len)| {
            (
                Regex::new(shape).expect("secret key shape compiles"),
                *min_len,
            )
        })
        .collect()
});

/// Finds API keys and tokens by their issuer shape.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretRecognizer;

impl SecretRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for SecretRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Secret]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let mut spans = Self::main_spans(text);
        for (start, end) in super::secret_link::link_scan(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        for (start, end) in lower_aws_keys(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        // Only a span no older span holds is added.
        let mut held: Vec<(usize, usize)> = spans.iter().map(|s| (s.start, s.end)).collect();
        held.sort_unstable();
        let mut reach = 0;
        let reaches: Vec<usize> = held
            .iter()
            .map(|&(_, end)| {
                reach = reach.max(end);
                reach
            })
            .collect();
        for (start, end) in super::secret_prose::prose_scan(text) {
            let before = held.partition_point(|&(from, _)| from <= start);
            if before == 0 || reaches[before - 1] < end {
                spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
            }
        }
        // An extra view, unioned with the scans above.
        for (start, end) in unescaped_keys(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        // An extra view, unioned with the scans above.
        for (start, end) in glued_keys(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        // Cookies, label lines, secret CSV columns, glued AWS ids.
        for (start, end) in super::secret_lines::lines_scan(text) {
            spans.push(Span::new(EntityKind::Secret, start, end, SCORE, NAME));
        }
        to_line_ends(text, &mut spans);
        spans
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

impl SecretRecognizer {
    /// Every scan before the link scan, unchanged: `link_scan` only adds to it.
    pub(crate) fn main_spans(text: &str) -> Vec<Span> {
        // Non-ASCII text is read through a view that drops zero-width characters
        // and maps fullwidth ASCII and dash variants; ASCII text is read as it is.
        let view = KeyView::for_text(text);
        let haystack = view.as_ref().map_or(text, |view| view.text.as_str());
        let original = |start: usize, end: usize| {
            view.as_ref()
                .map_or((start, end), |view| view.original(start, end))
        };
        let mut spans = Vec::new();
        for (shape, min_len) in SHAPES_RE.iter() {
            // The end of the last key this shape joined: a match inside it is
            // already covered, so its lines are not walked again.
            let mut consumed = 0;
            for captures in shape.captures_iter(haystack) {
                let Some(found) = captures.get(1).or_else(|| captures.get(0)) else {
                    continue;
                };
                if found.end() <= consumed {
                    continue;
                }
                let key = found.as_str();
                // Only the dotted ya29. shape matches a second dot after `ya29.`.
                let dotted = key.starts_with("eyJ")
                    || key.starts_with("SG.")
                    || key
                        .strip_prefix("ya29.")
                        .is_some_and(|rest| rest.contains('.'));
                let alphabet: fn(char) -> bool = if dotted {
                    is_dotted_key_char
                } else {
                    is_key_char
                };
                let mut end = join_wrapped(haystack, found.end(), alphabet);
                // `task-sk-<key>_build_id` presents a boundary-delimited `sk-`
                // after an identifier. Treat that ambiguous form like the
                // glued scan: validate the legacy key body and stop at it.
                if key.starts_with("sk-")
                    && found.start() >= 2
                    && haystack.as_bytes()[found.start() - 1] == b'-'
                    && haystack.as_bytes()[found.start() - 2].is_ascii_alphanumeric()
                {
                    let candidate = &haystack[found.start()..end];
                    if candidate.len() >= 51 && known_glued_format(&candidate[..51]) {
                        end = found.start() + 51;
                    }
                }
                consumed = end;
                if end - found.start() >= *min_len {
                    let (from, to) = original(found.start(), end);
                    spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
                }
            }
        }
        for captures in AWS_SECRET_RE.captures_iter(haystack) {
            if let Some(value) = captures.get(1) {
                // A wrapped value joins its continuation lines.
                let end = join_wrapped(haystack, value.end(), is_value_char);
                let (from, to) = original(value.start(), end);
                spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
            }
        }
        for value in secret_values(haystack) {
            let (from, to) = original(value.start, value.end);
            spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
        }
        // The DSN shape needs `://`, so a text without it skips that scan; a
        // scheme-less userinfo is read by its own shape.
        if haystack.contains("://") {
            for captures in DSN_USERINFO_RE.captures_iter(haystack) {
                let (Some(user), Some(password)) = (captures.get(1), captures.get(2)) else {
                    continue;
                };
                let start = if user.is_empty() {
                    password.start()
                } else {
                    user.start()
                };
                let (from, to) = original(start, password.end());
                spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
            }
        }
        for captures in DSN_NO_SCHEME_RE.captures_iter(haystack) {
            let (Some(user), Some(password)) = (captures.get(1), captures.get(2)) else {
                continue;
            };
            let (from, to) = original(user.start(), password.end());
            spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
        }
        for captures in AWS_PAIR_RE.captures_iter(haystack) {
            if let Some(secret) = captures.get(1) {
                // A 40-character prefix of a longer run is no key.
                if haystack[secret.end()..]
                    .chars()
                    .next()
                    .is_some_and(is_value_char)
                {
                    continue;
                }
                let (from, to) = original(secret.start(), secret.end());
                spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
            }
        }
        for captures in AUTHORIZATION_RE.captures_iter(haystack) {
            if let Some(value) = captures.get(1) {
                let (from, to) = original(value.start(), value.end());
                spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
            }
        }
        for block in PUTTY_KEY_RE
            .find_iter(haystack)
            .chain(HEADERLESS_PEM_RE.find_iter(haystack))
            .chain(PEM_BLOCK_RE.find_iter(haystack))
        {
            let (from, to) = original(block.start(), block.end());
            spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
        }
        for (shape, min_len) in VALUE_SHAPES_RE.iter() {
            for captures in shape.captures_iter(haystack) {
                let value = captures.get(1).or_else(|| captures.get(0));
                if let Some(value) = value.filter(|value| value.len() >= *min_len) {
                    let (from, to) = original(value.start(), value.end());
                    spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
                }
            }
        }
        for (start, end) in shape_values(haystack) {
            let (from, to) = original(start, end);
            spans.push(Span::new(EntityKind::Secret, from, to, SCORE, NAME));
        }
        spans
    }
}

/// An escaped key or a dotted `ya29.` token was read
/// before only by the gate's residue round, which masks a secret on to the
/// trimmed end of its line. Each such key keeps that run here, so no byte the
/// residue round masked is left clear. Spans are only widened, never narrowed;
/// each line end is searched once (linear).
fn to_line_ends(text: &str, spans: &mut [Span]) {
    let new_rule = |span: &Span| {
        let key = text.get(span.start..span.end).unwrap_or("");
        key.contains("\\_")
            || key.contains("\\-")
            || key
                .strip_prefix("ya29.")
                .is_some_and(|rest| rest.contains('.'))
    };
    let mut picked: Vec<&mut Span> = spans.iter_mut().filter(|span| new_rule(span)).collect();
    picked.sort_unstable_by_key(|span| span.end);
    let (mut reach, mut line, mut trimmed) = (0, usize::MAX, 0);
    for span in picked {
        let from = span.end.max(reach).min(text.len());
        let end = text[from..].find('\n').map_or(text.len(), |n| from + n);
        if end != line {
            line = end;
            trimmed = text[..line].trim_end().len();
        }
        reach = line;
        span.end = span.end.max(trimmed);
    }
}

// The submodules are private on purpose: every item below is re-exported at
// this path, so `kernel_privacy::recognizers::secrets::…` is exactly what it
// was before the split, and no new public path appears.

mod code;
mod formats;
mod glued;
mod key_names;
mod key_values;
mod key_view;
mod phrase;
mod prose;
mod tail;

pub use self::code::CuedCodeRecognizer;
pub use self::formats::value_too_long;
pub(super) use self::phrase::one_of;
pub(crate) use self::tail::linked_clause_end;

#[cfg(test)]
mod tests;
