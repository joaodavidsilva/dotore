use dotore_core::RuleId;

use super::extract_safety_findings;
use crate::matchers::RsCandidateFinding;

#[cfg(test)]
fn check_cast_findings(src: &str) -> Vec<RsCandidateFinding> {
    let Ok(ast) = syn::parse_file(src) else {
        return Vec::new();
    };
    let lines: Vec<&str> = src.lines().collect();
    let line_starts = dotore_core::compute_line_starts(src);
    let mut findings = Vec::new();
    extract_safety_findings(&ast, &lines, &line_starts, &mut findings);
    findings
        .into_iter()
        .filter(|f| f.rule == RuleId::RsNoLossyNumericAsCast)
        .collect()
}

#[cfg(test)]
fn check_slice_index_findings(src: &str) -> Vec<RsCandidateFinding> {
    let Ok(ast) = syn::parse_file(src) else {
        return Vec::new();
    };
    let lines: Vec<&str> = src.lines().collect();
    let line_starts = dotore_core::compute_line_starts(src);
    let mut findings = Vec::new();
    extract_safety_findings(&ast, &lines, &line_starts, &mut findings);
    findings
        .into_iter()
        .filter(|f| f.rule == RuleId::RsNoUnguardedSliceIndex)
        .collect()
}

#[test]
fn while_loop_and_short_circuit_boolean_guards_protect_slice_indexing() {
    let src = r#"
pub fn scan_bytes(bytes: &[u8], p: &[u8], t: &[u8]) -> usize {
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos] != b'\n' {
        if bytes[pos] == b'\\' {
            pos += 1;
        }
        pos += 1;
    }
    let pi = 0usize;
    let ti = 0usize;
    if pi < p.len() && ti < t.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
        pos += 1;
    }
    if pos >= bytes.len() || bytes[pos] == b'(' {
        pos += 1;
    }
    pos
}
"#;
    let findings = check_slice_index_findings(src);
    assert!(
        findings.is_empty(),
        "Expected 0 slice index findings for while/short-circuit guards, got: {findings:#?}"
    );
}

#[test]
fn exact_and_min_length_comparisons_and_arithmetic_offsets_guard_slice_indexing() {
    let src = r#"
pub fn length_and_offset_guards(
    tokens: &[&str],
    parts: &[&str],
    scc: &[usize],
    bytes: &[u8],
    components: &[&str],
    idx: usize,
) -> usize {
    let mut acc = 0usize;
    if tokens.len() >= 3 {
        acc += tokens[0].len() + tokens[1].len() + tokens[2].len();
    }
    if parts.len() == 3 {
        acc += parts[0].len() + parts[1].len() + parts[2].len();
    }
    if scc.len() > 1 {
        acc += scc[0] + scc[1];
    }
    if idx + 1 < bytes.len() {
        acc += usize::from(bytes[idx]) + usize::from(bytes[idx + 1]);
    }
    if idx > 0 && idx < bytes.len() {
        acc += usize::from(bytes[idx - 1]);
    }
    if components.len() >= 3 {
        acc += components[..components.len() - 2].len();
        acc += components[components.len() - 1].len();
    }
    if scc.len() != 2 {
        return acc;
    }
    acc + scc[0] + scc[1]
}
"#;
    let findings = check_slice_index_findings(src);
    assert!(
        findings.is_empty(),
        "Expected 0 slice index findings for length and arithmetic offset guards, got: {findings:#?}"
    );
}

#[test]
fn bounded_for_loops_const_arrays_windows_modulo_read_exact_and_parallel_vecs_are_guarded() {
    let src = r#"
const SHA256_K: [u32; 64] = [0; 64];
const SPINNER_FRAMES: &[char] = &['a', 'b', 'c', 'd'];

pub struct Reader;
impl Reader {
    fn read_exact_bytes(&mut self, n: usize) -> Result<Vec<u8>, String> {
        Ok(vec![0; n])
    }
}

pub fn idioms(
    items: &[u32],
    render_calls: &[(u32, u32)],
    tick: usize,
    reader: &mut Reader,
) -> Result<u32, String> {
    let mut w = [0u32; 64];
    for i in 16..64 {
        w[i] = w[i - 16].wrapping_add(w[i - 15]).wrapping_add(w[i - 7]).wrapping_add(w[i - 2]);
    }
    let mut acc = 0u32;
    for i in 0..64 {
        acc = acc.wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
    }
    for i in 1..render_calls.len() {
        if render_calls[i].0 == render_calls[i - 1].0 {
            acc += render_calls[i].1;
        }
    }
    for window in items.windows(2) {
        acc += window[0] + window[1];
    }
    let mask = [1u8, 2, 3, 4];
    for (idx, _) in items.iter().enumerate() {
        acc += items[idx] + u32::from(mask[idx % 4]);
    }
    let _ch = SPINNER_FRAMES[tick % SPINNER_FRAMES.len()];
    let hdr = reader.read_exact_bytes(2)?;
    let ext = reader.read_exact_bytes(8)?;
    acc += u32::from(hdr[0]) + u32::from(hdr[1]) + u32::from(ext[7]);

    let n = items.len();
    let mut visited = vec![false; n];
    let mut buckets: Vec<Vec<u32>> = (0..items.len()).map(|_| Vec::new()).collect();
    for idx in 0..n {
        if !visited[idx] {
            visited[idx] = true;
            buckets[idx].push(items[idx]);
        }
    }
    Ok(acc)
}
"#;
    let findings = check_slice_index_findings(src);
    assert!(
        findings.is_empty(),
        "Expected 0 slice index findings for bounded loops/arrays/windows/modulo/parallel vecs, got: {findings:#?}"
    );
}

#[test]
fn search_clamp_read_as_bytes_and_json_key_indexing_are_guarded() {
    let src = r#"
pub fn search_and_clamp_idioms(
    raw_url: &str,
    source: &str,
    byte_pos: usize,
    prop_lines: &[(u32, &str)],
    line: &str,
    stream: &mut dyn std::io::Read,
    val: &serde_json::Value,
) -> Result<usize, String> {
    let mut acc = 0usize;
    let (_, after_scheme) = raw_url.split_once("://").unwrap_or(("http", raw_url));
    let (authority, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, "/"),
    };
    acc += authority.len() + path.len();

    if let Some(open_paren) = line.find('(')
        && line.ends_with(')')
    {
        let callee = line[..open_paren].trim();
        let args = &line[open_paren + 1..line.len() - 1];
        acc += callee.len() + args.len();
    }

    let prefix = &source[..byte_pos.min(source.len())];
    let line_start = prefix.rfind('\n').map_or(0, |idx| idx + 1);
    acc += source[line_start..byte_pos.min(source.len())].len();

    if !prop_lines.is_empty() {
        let visible_count = prop_lines.len().min(10);
        let visible = &prop_lines[..visible_count];
        acc += visible[0].1.len();
    }

    if line.len() >= 7 && &line.as_bytes()[4..7] == b" | " {
        acc += 7;
    }
    if let Some(fetch_pos) = line.find("fetch(")
        && fetch_pos > 0
        && line.as_bytes()[fetch_pos - 1].is_ascii_alphanumeric()
    {
        acc += 1;
    }

    let mut temp = [0u8; 512];
    let n = stream.read(&mut temp).map_err(|e| e.to_string())?;
    acc += temp[..n].len();

    let _session = &val["result"]["value"];
    Ok(acc)
}
"#;
    let findings = check_slice_index_findings(src);
    assert!(
        findings.is_empty(),
        "Expected 0 slice index findings for search/clamp/read/as_bytes/json key idioms, got: {findings:#?}"
    );
}

#[test]
fn substring_search_offsets_match_indices_binary_search_and_cursor_decrement_are_guarded() {
    let src = r#"
pub fn substring_and_cursor_idioms(
    source: &str,
    pattern: &str,
    glsl: &str,
    needle: &str,
    haystack: &str,
    ident: &str,
    lines: &[&str],
    start_idx: usize,
) -> Option<usize> {
    let mut acc = 0usize;
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find(pattern) {
        let hit = search_from + rel;
        let after_name = &source[hit + pattern.len()..];
        acc += after_name.len();
        search_from = hit + pattern.len();
    }

    let start = glsl.find(needle)? + needle.len();
    let end = glsl[start..].find(')')? + start;
    acc += glsl[start..end].len();

    for (idx, _) in haystack.match_indices(ident) {
        let before_ok = idx == 0 || !haystack.as_bytes()[idx - 1].is_ascii_alphanumeric();
        let after_idx = idx + ident.len();
        let after_ok = after_idx == haystack.len() || !haystack.as_bytes()[after_idx].is_ascii_alphanumeric();
        if before_ok && after_ok {
            acc += 1;
        }
    }

    let found = lines.binary_search(&needle).ok().map(|idx| lines[idx].len()).unwrap_or(0);
    acc += found;

    let mut cursor = start_idx.min(lines.len().saturating_sub(1));
    while cursor > 0 {
        cursor -= 1;
        acc += lines[cursor].len();
    }
    Some(acc)
}
"#;
    let findings = check_slice_index_findings(src);
    assert!(
        findings.is_empty(),
        "Expected 0 slice index findings for substring search, match_indices, binary_search, and cursor decrement, got: {findings:#?}"
    );
}

#[test]
fn char_indices_take_while_and_subslice_ranges_are_guarded() {
    let src = r#"
pub fn char_indices_and_subslice_idioms(
    spec: &str,
    stmt_line: &str,
    hint: &str,
    lines: &[&str],
) -> Option<usize> {
    let mut acc = 0usize;
    for (idx, ch) in spec.char_indices() {
        if ch == '=' {
            acc += spec[..idx].len() + spec[idx..].len();
        }
    }
    let indent_len = stmt_line.len() - stmt_line.trim_start().len();
    acc += stmt_line[..indent_len].len();

    if let Some(first) = hint.chars().next() {
        acc += hint[first.len_utf8()..].len();
    }

    for (i, _) in lines.iter().enumerate() {
        for &body_line in &lines[i + 1..] {
            acc += body_line.len();
        }
    }

    let len = spec.bytes().take_while(|b| b.is_ascii_alphanumeric()).count();
    acc += spec[..len].len();

    let open = spec.find('(')?;
    let after = &spec[open + 1..];
    acc += after.len();

    Some(acc)
}
"#;
    let findings = check_slice_index_findings(src);
    assert!(
        findings.is_empty(),
        "Expected 0 slice index findings for char_indices/take_while/subslice, got: {findings:#?}"
    );
}

#[test]
fn lowercase_as_bytes_equivalence_and_as_chunks_are_guarded() {
    let src = r#"
pub fn lowercase_and_chunks_idioms(
    line: &str,
    input: &str,
    padded: &[u8],
    h: [u32; 8],
) -> usize {
    let mut acc = 0usize;
    let l = line.to_ascii_lowercase();
    if let Some(pos) = l.find("create table") {
        acc += line[pos + "create table".len()..].len();
    }

    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(ch) = input[i..].chars().next() {
            acc += ch.len_utf8();
        }
        i += 1;
    }

    let mut w = [0u32; 64];
    for chunk in padded.as_chunks::<64>().0 {
        for (idx, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[idx] = u32::from_be_bytes(*word);
        }
    }
    let mut out = [0u8; 32];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    acc += usize::from(out[0]) + (w[0] as usize);
    acc
}
"#;
    let findings = check_slice_index_findings(src);
    assert!(
        findings.is_empty(),
        "Expected 0 slice index findings for lowercase/as_bytes equivalence and as_chunks, got: {findings:#?}"
    );
}

#[test]
fn unguarded_slice_and_string_indexing_sites_including_s_and_files_are_flagged() {
    let src = r#"
pub fn unguarded_sites(
    items: &[u64],
    groups: &[u32],
    hex: &str,
    s: &str,
    files: &[&str],
    idx: usize,
) -> u64 {
    let a = items[idx];
    let b = u64::from(groups[0]);
    let c = hex[0..2].len() as u64;
    let d = (&s[0..5]).len() as u64;
    let e = files[idx].len() as u64;
    a + b + c + d + e
}
"#;
    let findings = check_slice_index_findings(src);
    assert_eq!(
        findings.len(),
        5,
        "Expected all 5 unguarded slice/string index sites (including `&s[0..5]` and `files[idx]`) to be flagged, got: {findings:#?}"
    );
}

#[test]
fn widening_span_fields_masked_casts_from_bytes_and_enum_discriminants_are_lossless() {
    let src = r#"
#[repr(u16)]
#[derive(Clone, Copy)]
pub enum Kind {
    A = 0,
    B = 1,
}

impl Kind {
    pub const fn index(self) -> usize {
        self as usize
    }
}

pub struct Span {
    pub start: u32,
    pub end: u32,
    pub line: u32,
    pub column: u32,
    pub index: u32,
    pub health_score: u8,
}

pub fn lossless_casts(span: Span, hdr: &[u8], ext: [u8; 2], buf: u32, bits: u32, text: &str) -> usize {
    let a = span.start as usize;
    let b = span.end.saturating_sub(span.start) as usize;
    let c = (span.line - 1) as usize;
    let d = span.column as usize + span.index as usize + span.health_score as usize;
    let e = ((buf >> bits) & 0xff) as u8;
    let f = (hdr.get(1).copied().unwrap_or(0) & 0x7f) as usize;
    let g = u16::from_be_bytes(ext) as usize;
    let h = u8::from_le_bytes([ext[0]]) as u32;
    let mut char_sum = 0u32;
    for ch in text.chars() {
        char_sum += ch as u32;
    }
    a + b + c + d + usize::from(e) + f + g + (h as usize) + (char_sum as usize)
}
"#;
    let findings = check_cast_findings(src);
    assert!(
        findings.is_empty(),
        "Expected 0 lossy cast findings on lossless casts, got: {findings:#?}"
    );
}

#[test]
fn narrowing_sign_changing_float_to_int_and_overwide_mask_casts_are_flagged() {
    let src = r#"
pub struct NumLit {
    pub value: f64,
}

pub fn lossy_casts(
    big: u64,
    idx: usize,
    signed: i32,
    unsigned: u32,
    flt: f64,
    num: NumLit,
) -> usize {
    let a = big as u32;
    let b = idx as u32;
    let c = (big + 1) as u32;
    let d = signed as u32;
    let e = unsigned as i32;
    let f = flt as u32;
    let g = flt as usize;
    let h = num.value as usize;
    let i = signed as usize;
    let j = big as usize;
    let k = (big & 0x1ff) as u8;
    (a as usize) + (b as usize) + (c as usize) + (d as usize) + (e as usize) + (f as usize) + g + h + i + j + usize::from(k)
}
"#;
    let findings = check_cast_findings(src);
    assert_eq!(
        findings.len(),
        12,
        "Expected all 12 lossy casts (including `e as usize` from `i32`) to be flagged, got {}: {findings:#?}",
        findings.len()
    );
}
