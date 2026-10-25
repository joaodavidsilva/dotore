//! Deterministic credential redaction (`mask_credentials`) for diagnostic messages,
//! code frames, **Fix Capsules**, JSON/HTML/terminal reports, and agent handoff bundles.

struct CredentialPattern {
    prefix: &'static str,
    minimum_tail: usize,
    tail: fn(u8) -> bool,
}

const CREDENTIAL_PATTERNS: &[CredentialPattern] = &[
    CredentialPattern {
        prefix: "AKIA",
        minimum_tail: 16,
        tail: |byte| byte.is_ascii_uppercase() || byte.is_ascii_digit(),
    },
    CredentialPattern {
        prefix: "ghp_",
        minimum_tail: 36,
        tail: |byte| byte.is_ascii_alphanumeric(),
    },
    CredentialPattern {
        prefix: "github_pat_",
        minimum_tail: 22,
        tail: |byte| byte.is_ascii_alphanumeric() || byte == b'_',
    },
    CredentialPattern {
        prefix: "sk-",
        minimum_tail: 20,
        tail: |byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'),
    },
    CredentialPattern {
        prefix: "xoxb-",
        minimum_tail: 10,
        tail: |byte| byte.is_ascii_alphanumeric() || byte == b'-',
    },
    CredentialPattern {
        prefix: "xoxp-",
        minimum_tail: 10,
        tail: |byte| byte.is_ascii_alphanumeric() || byte == b'-',
    },
];

const DATABASE_SCHEMES: &[&str] = &[
    "mongodb",
    "mongodb+srv",
    "mysql",
    "postgres",
    "postgresql",
    "redis",
    "rediss",
];

const PLACEHOLDER_PASSWORDS: &[&str] = &[
    "changeme",
    "dummy",
    "example",
    "fake",
    "pass",
    "password",
    "placeholder",
    "sample",
];

const REDACTED: &str = "<redacted>";
const REDACTED_PREFIX_CHARS: usize = 4;
const REDACTED_MIN_CHARS: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RedactionKind {
    Token,
    DatabasePassword,
}

/// Redacts live credential literals (`AKIA...`, `ghp_...`, `github_pat_...`, `sk-...`, `xoxb-...`,
/// `-----BEGIN *PRIVATE KEY-----` blocks, and non-placeholder passwords in `postgres`/`mysql`/
/// `mongodb`/`redis` connection URLs) across `text` while preserving non-secret source text.
#[must_use]
pub fn mask_credentials(text: &str) -> String {
    if !might_contain_credential(text) {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len());
    let mut in_private_key = false;
    let mut changed = false;

    for (line_idx, line) in text.split('\n').enumerate() {
        if line_idx > 0 {
            out.push('\n');
        }
        if mask_private_key_line(line, &mut in_private_key, &mut out)
            || mask_credential_ranges_on_line(line, &mut out)
        {
            changed = true;
        } else {
            out.push_str(line);
        }
    }

    if changed { out } else { text.to_string() }
}

fn mask_private_key_line(line: &str, in_private_key: &mut bool, out: &mut String) -> bool {
    if *in_private_key {
        if let Some(end_pos) = find_private_key_end(line) {
            *in_private_key = false;
            out.push_str(REDACTED);
            out.push_str(line.get(end_pos..).unwrap_or_default());
        } else {
            out.push_str(REDACTED);
        }
        return true;
    }
    let Some((start, header_end)) = find_private_key_header(line) else {
        return false;
    };
    out.push_str(line.get(..start).unwrap_or_default());
    out.push_str("----");
    out.push_str(REDACTED);
    if let Some(end_pos) = find_private_key_end(line.get(header_end..).unwrap_or_default()) {
        out.push_str(line.get(header_end + end_pos..).unwrap_or_default());
    } else {
        *in_private_key = true;
    }
    true
}

fn mask_credential_ranges_on_line(line: &str, out: &mut String) -> bool {
    let ranges = credential_ranges_on_line(line);
    if ranges.is_empty() {
        return false;
    }
    let mut copied = 0;
    for (start, end, kind) in ranges {
        let start = start.max(copied);
        let (Some(before), Some(value)) = (line.get(copied..start), line.get(start..end)) else {
            continue;
        };
        if end <= start {
            continue;
        }
        out.push_str(before);
        match kind {
            RedactionKind::Token => out.push_str(&masked_token(value)),
            RedactionKind::DatabasePassword => out.push_str(REDACTED),
        }
        copied = end;
    }
    out.push_str(line.get(copied..).unwrap_or_default());
    true
}

fn might_contain_credential(text: &str) -> bool {
    text.contains("AKIA")
        || text.contains("ghp_")
        || text.contains("github_pat_")
        || text.contains("sk-")
        || text.contains("xoxb-")
        || text.contains("xoxp-")
        || text.contains("-----BEGIN ")
        || text.contains("://")
}

fn masked_token(value: &str) -> String {
    let kept: String = if value.chars().count() >= REDACTED_MIN_CHARS {
        value.chars().take(REDACTED_PREFIX_CHARS).collect()
    } else {
        String::new()
    };
    kept + REDACTED
}

fn credential_ranges_on_line(line: &str) -> Vec<(usize, usize, RedactionKind)> {
    let mut ranges: Vec<(usize, usize, RedactionKind)> = CREDENTIAL_PATTERNS
        .iter()
        .flat_map(|pattern| {
            pattern_ranges(line, pattern).map(|(s, e)| (s, e, RedactionKind::Token))
        })
        .chain(
            database_password_ranges(line)
                .into_iter()
                .map(|(s, e)| (s, e, RedactionKind::DatabasePassword)),
        )
        .collect();
    ranges.sort_unstable_by_key(|&(s, e, _)| (s, e));

    let mut disjoint: Vec<(usize, usize, RedactionKind)> = Vec::with_capacity(ranges.len());
    for (start, end, kind) in ranges {
        match disjoint.last_mut() {
            Some(last) if start < last.1 => {
                last.1 = last.1.max(end);
            }
            _ => disjoint.push((start, end, kind)),
        }
    }
    disjoint
}

fn pattern_ranges<'a>(
    line: &'a str,
    pattern: &'a CredentialPattern,
) -> impl Iterator<Item = (usize, usize)> + 'a {
    let bytes = line.as_bytes();
    let mut from = 0;
    std::iter::from_fn(move || {
        while let Some(offset) = line.get(from..)?.find(pattern.prefix) {
            let start = from + offset;
            let boundary = start
                .checked_sub(1)
                .and_then(|prev| bytes.get(prev))
                .is_none_or(|&b| !b.is_ascii_alphanumeric() && b != b'_');
            let tail_start = start + pattern.prefix.len();
            let tail_length = bytes
                .get(tail_start..)
                .unwrap_or_default()
                .iter()
                .take_while(|byte| (pattern.tail)(**byte))
                .count();
            from = tail_start;
            if boundary && tail_length >= pattern.minimum_tail {
                from = tail_start + tail_length;
                return Some((start, from));
            }
        }
        None
    })
}

fn find_private_key_header(line: &str) -> Option<(usize, usize)> {
    let start = line.find("-----BEGIN ")?;
    let label_start = start + "-----BEGIN ".len();
    let suffix = "PRIVATE KEY-----";
    let suffix_rel = line.get(label_start..)?.find(suffix)?;
    let suffix_start = label_start + suffix_rel;
    let label = line.get(label_start..suffix_start)?;
    label
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b == b' ')
        .then_some((start, suffix_start + suffix.len()))
}

fn find_private_key_end(line: &str) -> Option<usize> {
    let start = line.find("-----END ")?;
    let suffix = "PRIVATE KEY-----";
    let suffix_rel = line.get(start..)?.find(suffix)?;
    Some(start + suffix_rel + suffix.len())
}

fn database_password_ranges(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = line.get(from..).and_then(|rest| rest.find("://")) {
        let separator = from + offset;
        from = separator + 3;
        let scheme_start = line
            .get(..separator)
            .unwrap_or_default()
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')))
            .map_or(0, |idx| idx + 1);
        let scheme = line
            .get(scheme_start..separator)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !DATABASE_SCHEMES.contains(&scheme.as_str())
            || (scheme_start > 0 && bytes.get(scheme_start - 1) == Some(&b'_'))
        {
            continue;
        }
        let authority_end = line
            .get(from..)
            .unwrap_or_default()
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | '`'))
            .map_or(line.len(), |idx| from + idx);
        let authority = line.get(from..authority_end).unwrap_or_default();
        let Some(at) = authority.rfind('@') else {
            continue;
        };
        let user_info = authority.get(..at).unwrap_or_default();
        let Some(colon) = user_info.find(':') else {
            continue;
        };
        let password = user_info.get(colon + 1..).unwrap_or_default();
        if password.is_empty() || is_placeholder_password(password) {
            continue;
        }
        found.push((from + colon + 1, from + at));
    }
    found
}

fn is_placeholder_password(password: &str) -> bool {
    let wrapped = |open: &str, close: &str| password.starts_with(open) && password.ends_with(close);
    PLACEHOLDER_PASSWORDS.contains(&password.to_ascii_lowercase().as_str())
        || password.starts_with('$')
        || wrapped("<", ">")
        || wrapped("{", "}")
}
