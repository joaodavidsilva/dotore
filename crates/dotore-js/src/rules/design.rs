//! Single-pass UI design (`design` and `react-ui`) rule evaluators and deterministic `Autofix` patches.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants and JSX/CSS AST traversal matches only relevant node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::{
    AstKind,
    ast::{
        Expression, JSXAttribute, JSXAttributeValue, JSXChild, JSXElement, JSXOpeningElement,
        Program, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;

use crate::{
    ir::{
        ByteSpan, SourceLoc,
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{
        eval_numeric_expr, eval_static_str, find_attr, find_attr_ignore_case, get_attr_static_str,
        get_class_name_str, get_jsx_tag_name, get_style_prop_number, get_style_prop_str,
        subtree_has_tag_matching,
    },
    rules::{AutofixPatch, ByteEdit, RuleId},
};

const VAGUE_BUTTON_LABELS: &[&str] = &[
    "continue",
    "submit",
    "ok",
    "okay",
    "click here",
    "here",
    "yes",
    "no",
    "go",
    "done",
    "button",
    "link",
    "more",
];

const EXCLUDED_TYPOGRAPHY_TAGS: &[&str] = &[
    "code",
    "pre",
    "kbd",
    "samp",
    "var",
    "tt",
    "markdown",
    "mdx",
    "prose",
    "richtext",
    "blockquote",
    "trans",
    "translation",
];

const BLOCK_DEFAULT_TAGS: &[&str] = &[
    "div",
    "p",
    "section",
    "article",
    "main",
    "header",
    "footer",
    "nav",
    "aside",
    "figure",
    "figcaption",
    "blockquote",
    "form",
    "fieldset",
    "address",
    "pre",
    "ul",
    "ol",
    "dl",
    "dt",
    "dd",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
];

const INLINE_DEFAULT_TAGS: &[&str] = &[
    "span", "a", "b", "i", "em", "strong", "small", "code", "abbr", "cite", "label", "mark", "q",
    "s", "u", "sub", "sup", "kbd", "samp", "var", "time",
];

const LAYOUT_TRANSITION_PROPS: &[&str] = &[
    "width",
    "height",
    "min-width",
    "max-width",
    "min-height",
    "max-height",
    "top",
    "right",
    "bottom",
    "left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "border-width",
];

const GENERIC_MARKETING_PHRASES: &[&str] = &[
    "supercharge your workflow",
    "next-generation platform",
    "unlock the power of",
    "revolutionize the way",
    "seamless integration",
    "built for modern teams",
];

/// Extracts all single-pass `design` and `react-ui` rule sites (including deterministic `Autofix` patches).
#[must_use]
pub(crate) fn extract_design_sites(
    path: &std::path::Path,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
) -> Vec<SemanticRuleSite> {
    let mut sites = Vec::new();
    let mut const_strings: HashMap<SymbolId, String> = HashMap::new();
    let mut icon_families: HashSet<String> = HashSet::new();

    for (_, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::ImportDeclaration(imp) if !imp.import_kind.is_type() => {
                let src = imp.source.value.as_str().unwrap_or_default();
                if let Some(fam) = classify_icon_library_family(src)
                    && imp.specifiers.as_ref().is_some_and(|s| !s.is_empty())
                {
                    icon_families.insert(fam.to_string());
                }
            }
            AstKind::VariableDeclaration(var_decl)
                if var_decl.kind == VariableDeclarationKind::Const =>
            {
                for decl in &var_decl.declarations {
                    if let oxc_ast::ast::BindingPattern::BindingIdentifier(id) = &decl.id
                        && let Some(sym_id) = id.symbol_id.get()
                        && let Some(init) = &decl.init
                        && let Some(val) = eval_static_str(semantic, init, &const_strings)
                    {
                        const_strings.insert(sym_id, val);
                    }
                }
            }
            _ => {}
        }
    }

    if icon_families.len() >= 2 {
        push_design_site(
            &mut sites,
            RuleId::NoMixedIconLibraries,
            None,
            "noMixedIconLibraries",
            "icons",
            "This file mixes multiple icon libraries. Standardize on one icon family so stroke weight and proportions stay consistent.".to_string(),
            SourceLoc { line: 1, column: 1 },
            ByteSpan { start: 0, end: 0 },
            None,
        );
    }

    let mut did_report_redundant_size_axes = false;
    let mut did_report_z_index_9999 = false;
    let mut kicker_candidates: Vec<(SourceLoc, ByteSpan)> = Vec::new();

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::JSXAttribute(attr) => {
                check_jsx_attribute_design(
                    semantic,
                    node_id,
                    attr,
                    &subject_name,
                    &const_strings,
                    &mut did_report_redundant_size_axes,
                    &mut did_report_z_index_9999,
                    line_starts,
                    &mut sites,
                );
            }
            AstKind::JSXElement(jsx_el) => {
                check_jsx_element_design(
                    path,
                    semantic,
                    node_id,
                    jsx_el,
                    &subject_name,
                    &const_strings,
                    &mut kicker_candidates,
                    line_starts,
                    &mut sites,
                );
            }
            AstKind::TaggedTemplateExpression(tagged) => {
                check_tagged_template_design(
                    semantic,
                    tagged,
                    &subject_name,
                    line_starts,
                    &mut sites,
                );
            }
            AstKind::CallExpression(call)
                if !did_report_z_index_9999
                    && call
                        .callee
                        .span()
                        .source_text(semantic.source_text())
                        .contains("StyleSheet.create") =>
            {
                let call_src = call.span.source_text(semantic.source_text());
                if call_src.contains("zIndex: 9999") || call_src.contains("zIndex: 1000") {
                    did_report_z_index_9999 = true;
                    let loc = loc_from_line_starts(line_starts, call.span.start);
                    let span = ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    };
                    push_design_site(
                        &mut sites,
                        RuleId::NoZIndex9999,
                        subject_name.clone(),
                        "noZIndex9999",
                        "zIndex",
                        "z-index is unusually high and can hide a layering bug instead of fixing it.".to_string(),
                        loc,
                        span,
                        None,
                    );
                }
            }
            _ => {}
        }
    }

    if kicker_candidates.len() >= 3
        && let Some((loc, span)) = kicker_candidates.first().copied()
    {
        push_design_site(
            &mut sites,
            RuleId::NoRepeatedKickerLabels,
            None,
            "noRepeatedKickerLabels",
            "kicker",
            "The same uppercase tracked kicker repeats across several sections and makes the page feel templated.".to_string(),
            loc,
            span,
            None,
        );
    }

    let _ = program;
    sites
}

#[expect(
    clippy::too_many_arguments,
    reason = "Constructs a SemanticRuleSite with optional AutofixPatch directly"
)]
fn push_design_site(
    out: &mut Vec<SemanticRuleSite>,
    rule: RuleId,
    subject_name: Option<String>,
    message_id: &'static str,
    target_name: &str,
    message: String,
    loc: SourceLoc,
    span: ByteSpan,
    autofix: Option<AutofixPatch>,
) {
    out.push(SemanticRuleSite {
        rule,
        subject_name,
        message_id,
        target_name: target_name.to_string(),
        message,
        loc,
        span,
        autofix,
    });
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates className and style attribute design rules in one pass"
)]
fn check_jsx_attribute_design(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    attr: &JSXAttribute<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    did_report_redundant_size_axes: &mut bool,
    did_report_z_index_9999: &mut bool,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(ident) = attr.name.as_identifier() else {
        return;
    };
    let name = ident.name.as_str();
    let loc = loc_from_line_starts(line_starts, attr.span.start);
    let span = ByteSpan {
        start: attr.span.start,
        end: attr.span.end,
    };

    if name == "className" {
        if let Some(JSXAttributeValue::StringLiteral(s_lit)) = &attr.value
            && let Some(class_str) = s_lit.value.as_str()
        {
            let content_span = ByteSpan {
                start: s_lit.span.start + 1,
                end: s_lit.span.end.saturating_sub(1),
            };
            check_class_name_literal_design(
                class_str,
                content_span,
                subject_name,
                did_report_redundant_size_axes,
                loc,
                span,
                sites,
            );
        } else if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
            && let Some(Expression::TemplateLiteral(tpl)) = c.expression.as_expression()
            && !tpl.expressions.is_empty()
        {
            // `no-dynamic-tailwind-class-fragment`
            let has_fragment = tpl.quasis.iter().take(tpl.expressions.len()).any(|q| {
                let raw = q.value.raw.as_str();
                let tail = raw
                    .rsplit(|ch: char| ch.is_whitespace())
                    .next()
                    .unwrap_or(raw);
                let unvariant = tail
                    .rsplit(':')
                    .next()
                    .unwrap_or(tail)
                    .trim_start_matches(['!', '-']);
                unvariant.ends_with('-')
            });
            if has_fragment {
                push_design_site(
                    sites,
                    RuleId::NoDynamicTailwindClassFragment,
                    subject_name.clone(),
                    "noDynamicTailwindClassFragment",
                    "className",
                    "Tailwind cannot reliably discover this dynamically assembled utility. Write each complete class token as a static string.".to_string(),
                    loc_from_line_starts(line_starts, tpl.span.start),
                    ByteSpan {
                        start: tpl.span.start,
                        end: tpl.span.end,
                    },
                    None,
                );
            }
        }
    } else if name == "style" {
        check_inline_style_design(
            semantic,
            node_id,
            attr,
            subject_name,
            const_strings,
            did_report_z_index_9999,
            loc,
            span,
            line_starts,
            sites,
        );
    }
}

fn check_class_name_literal_design(
    class_str: &str,
    content_span: ByteSpan,
    subject_name: &Option<String>,
    did_report_redundant_size_axes: &mut bool,
    loc: SourceLoc,
    span: ByteSpan,
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tokens: Vec<&str> = class_str.split_whitespace().collect();

    // 1. `design-no-redundant-padding-axes` (with Autofix!)
    if class_str.contains("px-")
        && class_str.contains("py-")
        && !has_responsive_axis_prefix(&tokens, "px")
        && !has_responsive_axis_prefix(&tokens, "py")
    {
        let pairs = collect_matching_axis_values(&tokens, "px-", "py-");
        for val in pairs {
            let px_tok = format!("px-{val}");
            let py_tok = format!("py-{val}");
            let p_tok = format!("p-{val}");
            let mut new_tokens = Vec::with_capacity(tokens.len());
            let mut replaced = false;
            for &t in &tokens {
                if t == px_tok || t == py_tok {
                    if !replaced {
                        new_tokens.push(p_tok.as_str());
                        replaced = true;
                    }
                } else {
                    new_tokens.push(t);
                }
            }
            let patch = AutofixPatch {
                description: format!("Collapse `{px_tok} {py_tok}` to `{p_tok}`"),
                edits: vec![ByteEdit {
                    file: None,
                    span: content_span,
                    replacement: new_tokens.join(" "),
                }],
            };
            push_design_site(
                sites,
                RuleId::DesignNoRedundantPaddingAxes,
                subject_name.clone(),
                "designNoRedundantPaddingAxes",
                &p_tok,
                format!(
                    "{px_tok} and {py_tok} duplicate {p_tok}, so the class list is noisier without changing spacing."
                ),
                loc,
                span,
                Some(patch),
            );
        }
    }

    // 2. `design-no-redundant-size-axes` (once per file, with Autofix!)
    if !*did_report_redundant_size_axes
        && class_str.contains("w-")
        && class_str.contains("h-")
        && !has_responsive_axis_prefix(&tokens, "w")
        && !has_responsive_axis_prefix(&tokens, "h")
    {
        let pairs = collect_matching_axis_values(&tokens, "w-", "h-");
        if let Some(val) = pairs.into_iter().find(|v| !v.contains('/')) {
            *did_report_redundant_size_axes = true;
            let w_tok = format!("w-{val}");
            let h_tok = format!("h-{val}");
            let size_tok = format!("size-{val}");
            let mut new_tokens = Vec::with_capacity(tokens.len());
            let mut replaced = false;
            for &t in &tokens {
                if t == w_tok || t == h_tok {
                    if !replaced {
                        new_tokens.push(size_tok.as_str());
                        replaced = true;
                    }
                } else {
                    new_tokens.push(t);
                }
            }
            let patch = AutofixPatch {
                description: format!("Collapse `{w_tok} {h_tok}` to `{size_tok}`"),
                edits: vec![ByteEdit {
                    file: None,
                    span: content_span,
                    replacement: new_tokens.join(" "),
                }],
            };
            push_design_site(
                sites,
                RuleId::DesignNoRedundantSizeAxes,
                subject_name.clone(),
                "designNoRedundantSizeAxes",
                &size_tok,
                format!(
                    "{w_tok} and {h_tok} duplicate {size_tok}, so the class list is noisier without changing layout."
                ),
                loc,
                span,
                Some(patch),
            );
        }
    }

    // 3. `design-no-space-on-flex-children`
    let has_flex_or_grid = tokens.iter().any(|t| {
        let base = t.rsplit(':').next().unwrap_or(t);
        matches!(base, "flex" | "inline-flex" | "grid" | "inline-grid")
    });
    if has_flex_or_grid
        && let Some(space_tok) = tokens.iter().find(|t| {
            let base = t.rsplit(':').next().unwrap_or(t).trim_start_matches('-');
            base.starts_with("space-x-") || base.starts_with("space-y-")
        })
    {
        let base = space_tok
            .rsplit(':')
            .next()
            .unwrap_or(space_tok)
            .trim_start_matches('-');
        push_design_site(
            sites,
            RuleId::DesignNoSpaceOnFlexChildren,
            subject_name.clone(),
            "designNoSpaceOnFlexChildren",
            base,
            format!(
                "{base} on a flex or grid parent can leave uneven gaps when children hide, wrap, or render in RTL layouts."
            ),
            loc,
            span,
            None,
        );
    }

    // 4. `prefer-truncate-shorthand` (with Autofix!)
    if tokens.contains(&"overflow-hidden")
        && tokens.contains(&"text-ellipsis")
        && tokens.contains(&"whitespace-nowrap")
    {
        let mut new_tokens = Vec::with_capacity(tokens.len());
        let mut inserted = false;
        for &t in &tokens {
            if matches!(t, "overflow-hidden" | "text-ellipsis" | "whitespace-nowrap") {
                if !inserted {
                    new_tokens.push("truncate");
                    inserted = true;
                }
            } else {
                new_tokens.push(t);
            }
        }
        let patch = AutofixPatch {
            description: "Collapse `overflow-hidden text-ellipsis whitespace-nowrap` to `truncate`"
                .to_string(),
            edits: vec![ByteEdit {
                file: None,
                span: content_span,
                replacement: new_tokens.join(" "),
            }],
        };
        push_design_site(
            sites,
            RuleId::PreferTruncateShorthand,
            subject_name.clone(),
            "preferTruncateShorthand",
            "truncate",
            "`overflow-hidden text-ellipsis whitespace-nowrap` is exactly what the `truncate` utility does — collapse the three classes into `truncate`.".to_string(),
            loc,
            span,
            Some(patch),
        );
    }

    // 5. `no-deprecated-tailwind-class` (with Autofix!)
    for &t in &tokens {
        let base = t.rsplit(':').next().unwrap_or(t);
        let replacement_base = if base == "overflow-ellipsis" {
            Some("text-ellipsis".to_string())
        } else if base == "flex-shrink" || base.starts_with("flex-shrink-") {
            Some(base.replacen("flex-shrink", "shrink", 1))
        } else if base == "flex-grow" || base.starts_with("flex-grow-") {
            Some(base.replacen("flex-grow", "grow", 1))
        } else if matches!(
            base,
            "bg-gradient-to-t"
                | "bg-gradient-to-tr"
                | "bg-gradient-to-r"
                | "bg-gradient-to-br"
                | "bg-gradient-to-b"
                | "bg-gradient-to-bl"
                | "bg-gradient-to-l"
                | "bg-gradient-to-tl"
        ) {
            Some(base.replacen("bg-gradient-to-", "bg-linear-to-", 1))
        } else {
            None
        };
        if let Some(new_base) = replacement_base {
            let new_tokens: Vec<String> = tokens
                .iter()
                .map(|&tok| {
                    if tok == t {
                        new_base.clone()
                    } else {
                        tok.to_string()
                    }
                })
                .collect();
            let patch = AutofixPatch {
                description: format!("Replace deprecated `{base}` with `{new_base}`"),
                edits: vec![ByteEdit {
                    file: None,
                    span: content_span,
                    replacement: new_tokens.join(" "),
                }],
            };
            push_design_site(
                sites,
                RuleId::NoDeprecatedTailwindClass,
                subject_name.clone(),
                "noDeprecatedTailwindClass",
                base,
                format!(
                    "`{base}` is a legacy Tailwind name — use the canonical v4 utility `{new_base}`."
                ),
                loc,
                span,
                Some(patch),
            );
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all inline style design rules in one pass"
)]
fn check_inline_style_design(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    attr: &JSXAttribute<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    did_report_z_index_9999: &mut bool,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value else {
        return;
    };
    let Some(expr) = c.expression.as_expression() else {
        return;
    };
    let Expression::ObjectExpression(obj) = expr.without_parentheses() else {
        return;
    };

    let mut static_prop_count = 0_usize;
    let mut is_justified = false;
    let mut has_hyphens = false;
    let mut fg_color: Option<(f64, f64, f64)> = None;
    let mut bg_color: Option<(f64, f64, f64)> = None;
    let mut bg_str: Option<String> = None;
    let mut box_shadow_str: Option<String> = None;
    let mut border_str: Option<String> = None;
    let mut width_px: Option<f64> = None;
    let mut height_px: Option<f64> = None;

    for prop in &obj.properties {
        let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        let Some(key_name) = p.key.static_name() else {
            continue;
        };
        let Some(key) = key_name.as_str() else {
            continue;
        };
        let ploc = loc_from_line_starts(line_starts, p.span.start);
        let pspan = ByteSpan {
            start: p.span.start,
            end: p.span.end,
        };

        if is_static_style_literal(&p.value) {
            static_prop_count += 1;
        }

        let str_val = eval_static_str(semantic, &p.value, const_strings);
        let num_val = eval_numeric_expr(&p.value);

        if key == "zIndex" && !*did_report_z_index_9999 && num_val.is_some_and(|z| z >= 1000.0) {
            *did_report_z_index_9999 = true;
            push_design_site(
                sites,
                RuleId::NoZIndex9999,
                subject_name.clone(),
                "noZIndex9999",
                "zIndex",
                "z-index is unusually high and can hide a layering bug instead of fixing it."
                    .to_string(),
                ploc,
                pspan,
                None,
            );
        }

        if key == "textAlign" && str_val.as_deref() == Some("justify") {
            is_justified = true;
        }
        if matches!(key, "hyphens" | "WebkitHyphens") && str_val.as_deref() == Some("auto") {
            has_hyphens = true;
        }

        if matches!(key, "height" | "minHeight")
            && str_val
                .as_deref()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("100vh"))
        {
            push_design_site(
                sites,
                RuleId::PreferDvhOverVh,
                subject_name.clone(),
                "preferDvhOverVh",
                key,
                "`100vh` overflows under mobile browser toolbars; use `100dvh` or `h-dvh`."
                    .to_string(),
                ploc,
                pspan,
                None,
            );
        }

        if matches!(key, "width" | "minWidth")
            && str_val
                .as_deref()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("100vw"))
        {
            push_design_site(
                sites,
                RuleId::NoFullViewportWidth,
                subject_name.clone(),
                "noFullViewportWidth",
                key,
                "`100vw` ignores the scrollbar gutter and causes horizontal overflow; use `100%` or `w-full`.".to_string(),
                ploc,
                pspan,
                None,
            );
        }

        if key == "width" {
            width_px = num_val.or_else(|| str_val.as_deref().and_then(parse_px_or_rem));
        }
        if key == "height" {
            height_px = num_val.or_else(|| str_val.as_deref().and_then(parse_px_or_rem));
        }

        if matches!(key, "transition" | "transitionProperty")
            && let Some(v) = &str_val
        {
            let lower = v.to_ascii_lowercase();
            if !lower.split([',', ' ']).any(|t| t == "all")
                && let Some(lp) = lower
                    .split([',', ' '])
                    .find(|t| LAYOUT_TRANSITION_PROPS.contains(t))
            {
                push_design_site(
                    sites,
                    RuleId::NoLayoutTransitionInline,
                    subject_name.clone(),
                    "noLayoutTransitionInline",
                    lp,
                    format!(
                        "Animating layout property `{lp}` triggers relayout every frame; animate `transform` and `opacity` instead."
                    ),
                    ploc,
                    pspan,
                    None,
                );
            }
        }

        if matches!(
            key,
            "transition" | "transitionDuration" | "animation" | "animationDuration"
        ) && let Some(v) = &str_val
            && has_duration_over_1000ms(v)
            && !v.contains("infinite")
            && !v.contains("forwards")
        {
            push_design_site(
                sites,
                RuleId::NoLongTransitionDuration,
                subject_name.clone(),
                "noLongTransitionDuration",
                key,
                "Transition duration exceeds 1000ms; keep UI transitions fast.".to_string(),
                ploc,
                pspan,
                None,
            );
        }

        if matches!(
            key,
            "transition" | "transitionTimingFunction" | "animation" | "animationTimingFunction"
        ) && let Some(v) = &str_val
        {
            let lower = v.to_ascii_lowercase();
            if lower.split([',', ' ']).any(|t| t == "ease-in") {
                push_design_site(
                    sites,
                    RuleId::NoEaseInMotion,
                    subject_name.clone(),
                    "noEaseInMotion",
                    key,
                    "Ease-in delays the visible response; use ease-out for UI transitions."
                        .to_string(),
                    ploc,
                    pspan,
                    None,
                );
            }
            if lower.contains("bounce") || lower.contains("elastic") {
                push_design_site(
                    sites,
                    RuleId::NoInlineBounceEasing,
                    subject_name.clone(),
                    "noInlineBounceEasing",
                    key,
                    "Avoid bouncy easing animations on standard UI elements.".to_string(),
                    ploc,
                    pspan,
                    None,
                );
            }
        }

        if key == "letterSpacing" {
            let em_val = num_val.map(|px| px / 16.0).or_else(|| {
                let s = str_val.as_deref()?.trim();
                if let Some(em) = s.strip_suffix("em") {
                    em.parse::<f64>().ok()
                } else if let Some(px) = s.strip_suffix("px") {
                    px.parse::<f64>().ok().map(|v| v / 16.0)
                } else {
                    None
                }
            });
            if let Some(em) = em_val {
                if em < -0.08 {
                    push_design_site(
                        sites,
                        RuleId::NoCrushedLetterSpacing,
                        subject_name.clone(),
                        "noCrushedLetterSpacing",
                        "letterSpacing",
                        format!("This {em:.2}em tracking compresses letterforms excessively."),
                        ploc,
                        pspan,
                        None,
                    );
                } else if em > 0.05 {
                    push_design_site(
                        sites,
                        RuleId::NoWideLetterSpacing,
                        subject_name.clone(),
                        "noWideLetterSpacing",
                        "letterSpacing",
                        "Wide letter-spacing on body text hurts readability.".to_string(),
                        ploc,
                        pspan,
                        None,
                    );
                }
            }
        }

        if key == "color"
            && let Some(v) = &str_val
        {
            fg_color = parse_hex_or_rgb_color(v);
        }
        if matches!(key, "background" | "backgroundColor" | "backgroundImage")
            && let Some(v) = &str_val
        {
            if key != "backgroundImage" && bg_color.is_none() {
                bg_color = parse_hex_or_rgb_color(v);
            }
            bg_str = Some(v.clone());
            let lower = v.to_ascii_lowercase();
            if lower.contains("repeating-linear-gradient(")
                || lower.contains("repeating-radial-gradient(")
                || lower.contains("repeating-conic-gradient(")
            {
                push_design_site(
                    sites,
                    RuleId::NoRepeatingGradientDecoration,
                    subject_name.clone(),
                    "noRepeatingGradientDecoration",
                    key,
                    "Surface uses a repeating gradient texture.".to_string(),
                    ploc,
                    pspan,
                    None,
                );
            }
            if lower.matches("linear-gradient(").count() >= 2 {
                push_design_site(
                    sites,
                    RuleId::NoDecorativeGridBackground,
                    subject_name.clone(),
                    "noDecorativeGridBackground",
                    key,
                    "Surface draws a decorative coordinate grid background.".to_string(),
                    ploc,
                    pspan,
                    None,
                );
            }
        }
        if key == "boxShadow"
            && let Some(v) = &str_val
        {
            box_shadow_str = Some(v.clone());
            let lower = v.to_ascii_lowercase();
            if lower.contains("#000")
                || lower.contains("black")
                || lower.contains("rgb(0, 0, 0)")
                || lower.contains("rgba(0, 0, 0, 1)")
            {
                push_design_site(
                    sites,
                    RuleId::NoPureBlackShadow,
                    subject_name.clone(),
                    "noPureBlackShadow",
                    "boxShadow",
                    "This shadow uses pure black; tint shadows or use a softer neutral token."
                        .to_string(),
                    ploc,
                    pspan,
                    None,
                );
            }
        }
        if matches!(key, "border" | "borderWidth")
            && let Some(v) = &str_val
        {
            border_str = Some(v.clone());
        }
    }

    if static_prop_count >= 8 && subject_name.is_some() {
        push_design_site(
            sites,
            RuleId::NoInlineExhaustiveStyle,
            subject_name.clone(),
            "noInlineExhaustiveStyle",
            "style",
            format!(
                "This inline style has {static_prop_count} properties, which is hard to read & rebuilds every render."
            ),
            loc,
            span,
            None,
        );
    }

    if is_justified && !has_hyphens {
        push_design_site(
            sites,
            RuleId::NoJustifiedText,
            subject_name.clone(),
            "noJustifiedText",
            "textAlign",
            "Justified text without `hyphens: auto` creates uneven gaps between words.".to_string(),
            loc,
            span,
            None,
        );
    }

    if let (Some(fg), Some(bg)) = (fg_color, bg_color) {
        let ratio = wcag_contrast_ratio(fg, bg);
        if ratio < 4.5 {
            push_design_site(
                sites,
                RuleId::NoLowContrastInlineStyle,
                subject_name.clone(),
                "noLowContrastInlineStyle",
                "color",
                format!("Inline text contrast ratio is {ratio:.2}:1 (below WCAG 4.5:1 minimum)."),
                loc,
                span,
                None,
            );
        }
    }

    if let (Some(bg), Some(shadow)) = (bg_color, &box_shadow_str)
        && bg.0 <= 35.0
        && bg.1 <= 35.0
        && bg.2 <= 35.0
        && (shadow.contains("rgb") || shadow.contains('#'))
        && !shadow.contains("0, 0, 0")
    {
        push_design_site(
            sites,
            RuleId::NoDarkModeGlow,
            subject_name.clone(),
            "noDarkModeGlow",
            "boxShadow",
            "Colored glow shadow on a dark background.".to_string(),
            loc,
            span,
            None,
        );
    }

    if let (Some(border), Some(shadow)) = (&border_str, &box_shadow_str)
        && border.contains("1px")
        && (shadow.contains("20px") || shadow.contains("24px") || shadow.contains("30px"))
    {
        push_design_site(
            sites,
            RuleId::NoHairlineBorderWideShadow,
            subject_name.clone(),
            "noHairlineBorderWideShadow",
            "boxShadow",
            "Hairline border is paired with a wide diffuse shadow.".to_string(),
            loc,
            span,
            None,
        );
    }

    if let Some(bg_s) = &bg_str
        && bg_s.to_ascii_lowercase().contains("radial-gradient(")
        && bg_s.to_ascii_lowercase().contains("transparent")
    {
        if width_px.is_some_and(|w| w >= 240.0) && height_px.is_some_and(|h| h >= 160.0) {
            push_design_site(
                sites,
                RuleId::NoDecorativeRadialSpotlight,
                subject_name.clone(),
                "noDecorativeRadialSpotlight",
                "backgroundImage",
                "Large decorative radial spotlight gradient.".to_string(),
                loc,
                span,
                None,
            );
        } else if bg_color.is_some_and(|c| c.0 <= 35.0 && c.1 <= 35.0 && c.2 <= 35.0) {
            push_design_site(
                sites,
                RuleId::NoRadialHalo,
                subject_name.clone(),
                "noRadialHalo",
                "backgroundImage",
                "Saturated radial halo on a dark background surface.".to_string(),
                loc,
                span,
                None,
            );
        }
    }
    let _ = node_id;
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all element- and page-level UI design rules in one pass"
)]
fn check_jsx_element_design(
    _path: &std::path::Path,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let tag = get_jsx_tag_name(&opening.name);
    let loc = loc_from_line_starts(line_starts, opening.span.start);
    let span = ByteSpan {
        start: opening.span.start,
        end: opening.span.end,
    };
    let class_str = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
    let tokens: Vec<&str> = class_str.split_whitespace().collect();
    let unvariant_tokens: Vec<&str> = tokens
        .iter()
        .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
        .collect();

    // 1. `design-no-vague-button-label` (with wizard `Continue` + `Back`/`Previous` form exemption!)
    if matches!(tag.as_str(), "button" | "Button")
        && let Some(label_text) = collect_direct_button_label_text(jsx_el)
    {
        let norm = normalize_button_label(&label_text);
        if VAGUE_BUTTON_LABELS.contains(&norm.as_str()) {
            let is_wizard_continue =
                norm == "continue" && enclosing_form_has_previous_step_control(semantic, node_id);
            if !is_wizard_continue {
                push_design_site(
                    sites,
                    RuleId::DesignNoVagueButtonLabel,
                    subject_name.clone(),
                    "designNoVagueButtonLabel",
                    &label_text,
                    format!(
                        "Screen reader users may not know what \"{label_text}\" does. Use a specific action label."
                    ),
                    loc,
                    span,
                    None,
                );
            }
        }
    }

    // 2. `design-no-three-period-ellipsis` & `design-no-em-dash-in-jsx-text` (with Autofix!)
    if !is_inside_excluded_typography_element(semantic, node_id, const_strings) {
        for child in &jsx_el.children {
            if let JSXChild::Text(t) = child {
                let raw = t.value.as_str();
                if has_word_three_period_ellipsis(raw) {
                    let tspan = ByteSpan {
                        start: t.span.start,
                        end: t.span.end,
                    };
                    let patch = AutofixPatch {
                        description: "Replace `...` with typographic ellipsis `…`".to_string(),
                        edits: vec![ByteEdit {
                            file: None,
                            span: tspan,
                            replacement: raw.replace("...", "…"),
                        }],
                    };
                    push_design_site(
                        sites,
                        RuleId::DesignNoThreePeriodEllipsis,
                        subject_name.clone(),
                        "designNoThreePeriodEllipsis",
                        "...",
                        "Use the typographic ellipsis character `…` instead of three periods `...`.".to_string(),
                        loc_from_line_starts(line_starts, t.span.start),
                        tspan,
                        Some(patch),
                    );
                }
                if raw.contains('—') && raw.split_whitespace().count() >= 5 {
                    let tspan = ByteSpan {
                        start: t.span.start,
                        end: t.span.end,
                    };
                    let patch = AutofixPatch {
                        description: "Replace em dash `—` with `--`".to_string(),
                        edits: vec![ByteEdit {
                            file: None,
                            span: tspan,
                            replacement: raw.replace('—', "--"),
                        }],
                    };
                    push_design_site(
                        sites,
                        RuleId::DesignNoEmDashInJsxText,
                        subject_name.clone(),
                        "designNoEmDashInJsxText",
                        "—",
                        "Avoid em dashes in UI copy; use simpler punctuation.".to_string(),
                        loc_from_line_starts(line_starts, t.span.start),
                        tspan,
                        Some(patch),
                    );
                }
            }
        }
    }

    // 3. `no-undersized-icon-button`
    if tag == "button"
        && !has_direct_visible_text(jsx_el)
        && jsx_el
            .children
            .iter()
            .any(|c| matches!(c, JSXChild::Element(_)))
    {
        let mut min_dim = get_style_prop_number(opening, "width")
            .or_else(|| get_style_prop_number(opening, "height"));
        for &u in &unvariant_tokens {
            if let Some(px) = parse_tailwind_size_px(u) {
                min_dim = Some(min_dim.map_or(px, |cur| cur.min(px)));
            }
        }
        if min_dim.is_some_and(|d| d > 0.0 && d < 24.0) {
            push_design_site(
                sites,
                RuleId::NoUndersizedIconButton,
                subject_name.clone(),
                "noUndersizedIconButton",
                "button",
                "This icon button target is smaller than 24×24 CSS pixels (WCAG 2.5.8)."
                    .to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // 4. `no-img-without-dimensions`
    if tag == "img" {
        let has_attr_dims = find_attr_ignore_case(&opening.attributes, "width").is_some()
            && find_attr_ignore_case(&opening.attributes, "height").is_some();
        let has_tw_dims = unvariant_tokens.iter().any(|u| {
            u.starts_with("size-")
                || u.starts_with("aspect-")
                || (unvariant_tokens.iter().any(|w| w.starts_with("w-"))
                    && unvariant_tokens.iter().any(|h| h.starts_with("h-")))
        });
        let has_style_dims = get_style_prop_number(opening, "width").is_some()
            && get_style_prop_number(opening, "height").is_some();
        if !has_attr_dims && !has_tw_dims && !has_style_dims {
            push_design_site(
                sites,
                RuleId::NoImgWithoutDimensions,
                subject_name.clone(),
                "noImgWithoutDimensions",
                "img",
                "This image reserves no dimensions or aspect ratio before loading, causing layout shift.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // 5. `no-emoji-heading-decoration`
    if matches!(tag.as_str(), "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
        let text = collect_all_static_text(jsx_el);
        if starts_with_emoji(text.trim_start()) {
            push_design_site(
                sites,
                RuleId::NoEmojiHeadingDecoration,
                subject_name.clone(),
                "noEmojiHeadingDecoration",
                &tag,
                "This heading uses emoji as decoration. Keep the heading typographic and move icons into a consistent icon system.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // 6. `no-decorative-pulse` & `no-pulsing-status-dot`
    if unvariant_tokens
        .iter()
        .any(|u| matches!(*u, "animate-pulse" | "animate-ping"))
    {
        let role_val = find_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings));
        let is_live_status = matches!(
            role_val.as_deref(),
            Some("status" | "progressbar" | "alert")
        ) || find_attr_ignore_case(&opening.attributes, "aria-busy").is_some();
        let text = collect_all_static_text(jsx_el);
        let lower_text = text.to_ascii_lowercase();
        let is_busy_copy = lower_text.contains("loading")
            || lower_text.contains("saving")
            || lower_text.contains("processing");

        if !is_live_status && !is_busy_copy {
            if !text.trim().is_empty() {
                push_design_site(
                    sites,
                    RuleId::NoDecorativePulse,
                    subject_name.clone(),
                    "noDecorativePulse",
                    &tag,
                    "Stable copy pulses continuously for attention; reserve pulsing motion for real in-progress feedback.".to_string(),
                    loc,
                    span,
                    None,
                );
            } else if unvariant_tokens.contains(&"rounded-full")
                && unvariant_tokens
                    .iter()
                    .any(|u| parse_tailwind_size_px(u).is_some_and(|px| (2.0..=16.0).contains(&px)))
            {
                push_design_site(
                    sites,
                    RuleId::NoPulsingStatusDot,
                    subject_name.clone(),
                    "noPulsingStatusDot",
                    &tag,
                    "Decorative status dot pulses continuously without live-region semantics."
                        .to_string(),
                    loc,
                    span,
                    None,
                );
            }
        }
    }

    // 7. `no-side-tab-border`
    if unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "border-l-4" | "border-l-8" | "border-r-4" | "border-r-8"
        )
    }) && unvariant_tokens.iter().any(|u| {
        u.starts_with("border-[")
            || (u.starts_with("border-")
                && !u.starts_with("border-gray-")
                && !u.starts_with("border-slate-")
                && !u.starts_with("border-zinc-")
                && !u.starts_with("border-neutral-")
                && !u.starts_with("border-stone-")
                && !matches!(
                    *u,
                    "border-l-4" | "border-l-8" | "border-r-4" | "border-r-8"
                ))
    }) {
        push_design_site(
            sites,
            RuleId::NoSideTabBorder,
            subject_name.clone(),
            "noSideTabBorder",
            &tag,
            "Thick one-sided colored stripe border; prefer a subtler surface treatment."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // 8. `no-smooth-scroll-without-reduced-motion`
    if tokens.contains(&"scroll-smooth")
        && !tokens
            .iter()
            .any(|t| t.starts_with("motion-safe:") || t.starts_with("motion-reduce:"))
    {
        push_design_site(
            sites,
            RuleId::NoSmoothScrollWithoutReducedMotion,
            subject_name.clone(),
            "noSmoothScrollWithoutReducedMotion",
            &tag,
            "`scroll-smooth` ignores `prefers-reduced-motion`; use `motion-safe:scroll-smooth`."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // 9. `no-repeated-container-text`
    if matches!(tag.as_str(), "article" | "aside" | "div" | "section")
        && is_tailwind_card_tokens(&unvariant_tokens)
    {
        let mut leaf_texts: HashMap<String, usize> = HashMap::new();
        collect_leaf_element_texts(jsx_el, &mut leaf_texts);
        if let Some((repeated_text, _)) = leaf_texts
            .into_iter()
            .find(|(txt, count)| *count >= 3 && (4..=48).contains(&txt.len()))
        {
            push_design_site(
                sites,
                RuleId::NoRepeatedContainerText,
                subject_name.clone(),
                "noRepeatedContainerText",
                &repeated_text,
                format!(
                    "This card container repeats {:?} across multiple distinct slots.",
                    repeated_text
                ),
                loc,
                span,
                None,
            );
        }
    }

    // 10. `no-flat-page-type-scale`
    if tag == "main" {
        let mut font_sizes: Vec<f64> = Vec::new();
        collect_subtree_font_sizes(jsx_el, semantic, const_strings, &mut font_sizes);
        font_sizes.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        font_sizes.dedup_by(|a, b| (*a - *b).abs() < 0.01);
        if font_sizes.len() >= 3
            && let (Some(&smallest), Some(&largest)) = (font_sizes.first(), font_sizes.last())
            && smallest > 0.0
            && (largest / smallest) < 2.0
        {
            push_design_site(
                sites,
                RuleId::NoFlatPageTypeScale,
                subject_name.clone(),
                "noFlatPageTypeScale",
                "main",
                format!(
                    "This page declares {} text sizes within less than a 2× range. Increase the hierarchy between supporting and display text.",
                    font_sizes.len()
                ),
                loc,
                span,
                None,
            );
        }
    }

    // 11. `no-redundant-display-class` (with Autofix!)
    if let Some(class_attr) = find_attr(&opening.attributes, "className")
        && let Some(JSXAttributeValue::StringLiteral(s_lit)) = &class_attr.value
    {
        let redundant_disp = if BLOCK_DEFAULT_TAGS.contains(&tag.as_str())
            && tokens.contains(&"block")
            && !tokens.iter().any(|t| {
                t.contains(":flex")
                    || t.contains(":grid")
                    || t.contains(":hidden")
                    || t.contains(":inline")
            }) {
            Some("block")
        } else if INLINE_DEFAULT_TAGS.contains(&tag.as_str())
            && tokens.contains(&"inline")
            && !tokens
                .iter()
                .any(|t| t.contains(":block") || t.contains(":flex") || t.contains(":hidden"))
        {
            Some("inline")
        } else {
            None
        };
        if let Some(disp) = redundant_disp {
            let new_tokens: Vec<&str> = tokens.iter().copied().filter(|&t| t != disp).collect();
            let content_span = ByteSpan {
                start: s_lit.span.start + 1,
                end: s_lit.span.end.saturating_sub(1),
            };
            let patch = AutofixPatch {
                description: format!("Remove redundant `{disp}` class on `<{tag}>`"),
                edits: vec![ByteEdit {
                    file: None,
                    span: content_span,
                    replacement: new_tokens.join(" "),
                }],
            };
            push_design_site(
                sites,
                RuleId::NoRedundantDisplayClass,
                subject_name.clone(),
                "noRedundantDisplayClass",
                disp,
                format!("`{disp}` is already the default display of `<{tag}>`."),
                loc,
                span,
                Some(patch),
            );
        }
    }

    // 12. Remaining className / element design rules
    check_remaining_element_design_rules(
        semantic,
        node_id,
        jsx_el,
        &tag,
        &tokens,
        &unvariant_tokens,
        subject_name,
        const_strings,
        kicker_candidates,
        loc,
        span,
        line_starts,
        sites,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates all remaining UI design rules on a JSXElement in a single pass"
)]
fn check_remaining_element_design_rules(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    tag: &str,
    tokens: &[&str],
    unvariant_tokens: &[&str],
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let text = collect_all_static_text(jsx_el);
    let trimmed_text = text.trim();
    let font_size =
        resolve_element_font_size_px(opening, unvariant_tokens, semantic, const_strings);

    // 1. `no-tiny-text`
    if !trimmed_text.is_empty()
        && font_size.is_some_and(|px| px > 0.0 && px < 12.0)
        && !unvariant_tokens.contains(&"sr-only")
    {
        push_design_site(
            sites,
            RuleId::NoTinyText,
            subject_name.clone(),
            "noTinyText",
            tag,
            "Text is smaller than 12px and hard to read.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 2. `no-gradient-text`
    if unvariant_tokens.contains(&"bg-clip-text")
        && unvariant_tokens.contains(&"text-transparent")
        && unvariant_tokens.iter().any(|u| {
            u.starts_with("bg-gradient-")
                || u.starts_with("bg-linear-")
                || u.starts_with("bg-radial")
        })
    {
        push_design_site(
            sites,
            RuleId::NoGradientText,
            subject_name.clone(),
            "noGradientText",
            tag,
            "Gradient text is harder to read; prefer solid text color.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 3. `prefer-dvh-over-vh` & `no-full-viewport-width` (Tailwind classes)
    if unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "h-screen" | "min-h-screen" | "h-[100vh]" | "min-h-[100vh]"
        )
    }) {
        push_design_site(
            sites,
            RuleId::PreferDvhOverVh,
            subject_name.clone(),
            "preferDvhOverVh",
            tag,
            "`h-screen` / `100vh` overflows under mobile browser toolbars; use `h-dvh` / `min-h-dvh`.".to_string(),
            loc,
            span,
            None,
        );
    }
    if unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "w-screen" | "min-w-screen" | "w-[100vw]" | "min-w-[100vw]"
        )
    }) {
        push_design_site(
            sites,
            RuleId::NoFullViewportWidth,
            subject_name.clone(),
            "noFullViewportWidth",
            tag,
            "`w-screen` / `100vw` ignores the scrollbar gutter; use `w-full`.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 4. `no-cramped-container-padding`
    if !trimmed_text.is_empty()
        && unvariant_tokens.iter().any(|u| u.starts_with("border"))
        && unvariant_tokens.iter().any(|u| {
            matches!(
                *u,
                "p-0.5" | "p-1" | "p-1.5" | "px-1" | "py-1" | "p-[2px]" | "p-[4px]"
            )
        })
    {
        push_design_site(
            sites,
            RuleId::NoCrampedContainerPadding,
            subject_name.clone(),
            "noCrampedContainerPadding",
            tag,
            "Bounded text container has cramped padding (< 8px).".to_string(),
            loc,
            span,
            None,
        );
    }

    // 5. `no-small-form-control-text`
    if matches!(tag, "input" | "select" | "textarea")
        && font_size.is_some_and(|px| px > 0.0 && px < 16.0)
    {
        push_design_site(
            sites,
            RuleId::NoSmallFormControlText,
            subject_name.clone(),
            "noSmallFormControlText",
            tag,
            format!(
                "Form control uses {}px text on mobile; use at least 16px to prevent auto-zoom.",
                font_size.unwrap_or(14.0)
            ),
            loc,
            span,
            None,
        );
    }

    // 6. `no-oversized-long-heading`
    if tag == "h1" && trimmed_text.len() >= 40 && font_size.is_some_and(|px| px >= 64.0) {
        push_design_site(
            sites,
            RuleId::NoOversizedLongHeading,
            subject_name.clone(),
            "noOversizedLongHeading",
            "h1",
            "Long sentence-length headline uses an oversized hero display scale (>= 64px)."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // 7. `no-hover-only-reveal`
    if tokens.contains(&"opacity-0")
        && tokens
            .iter()
            .any(|t| *t == "hover:opacity-100" || *t == "group-hover:opacity-100")
        && !tokens.iter().any(|t| {
            t.contains("focus:opacity-100")
                || t.contains("focus-visible:opacity-100")
                || t.contains("focus-within:opacity-100")
        })
    {
        push_design_site(
            sites,
            RuleId::NoHoverOnlyReveal,
            subject_name.clone(),
            "noHoverOnlyReveal",
            tag,
            "Content is revealed only on hover without a keyboard focus reveal.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 8. `no-mixed-animation-owners`
    if (tag.starts_with("motion.") || tag.starts_with("m."))
        && find_attr(&opening.attributes, "animate").is_some()
        && unvariant_tokens.iter().any(|u| u.starts_with("transition"))
    {
        push_design_site(
            sites,
            RuleId::NoMixedAnimationOwners,
            subject_name.clone(),
            "noMixedAnimationOwners",
            tag,
            "CSS transition and Motion `animate` both control properties on the same element."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // 9. `prefer-tabular-numeric-data`
    if tag == "td"
        && !has_tabular_nums_in_ancestry(semantic, node_id, const_strings)
        && jsx_el.children.iter().any(|c| {
            if let JSXChild::ExpressionContainer(ec) = c {
                let s = ec.span.source_text(semantic.source_text());
                s.contains(".toLocaleString(")
                    || s.contains(".toFixed(")
                    || s.contains("formatCurrency(")
            } else {
                false
            }
        })
    {
        push_design_site(
            sites,
            RuleId::PreferTabularNumericData,
            subject_name.clone(),
            "preferTabularNumericData",
            "td",
            "Table cell renders a formatted number without `tabular-nums`.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 10. `require-autoplay-video-poster`
    if tag == "video"
        && find_attr_ignore_case(&opening.attributes, "autoPlay").is_some()
        && find_attr_ignore_case(&opening.attributes, "poster").is_none()
    {
        push_design_site(
            sites,
            RuleId::RequireAutoplayVideoPoster,
            subject_name.clone(),
            "requireAutoplayVideoPoster",
            "video",
            "Autoplaying `<video>` has no `poster` frame.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 11. `require-scale-reveal-transform-origin`
    if find_attr_ignore_case(&opening.attributes, "role")
        .and_then(|a| get_attr_static_str(semantic, a, const_strings))
        .is_some_and(|r| matches!(r.as_str(), "menu" | "listbox"))
        && find_attr(&opening.attributes, "initial")
            .is_some_and(|a| a.span.source_text(semantic.source_text()).contains("scale"))
        && !unvariant_tokens.iter().any(|u| u.starts_with("origin-"))
        && get_style_prop_str(opening, "transformOrigin", semantic, const_strings).is_none()
    {
        push_design_site(
            sites,
            RuleId::RequireScaleRevealTransformOrigin,
            subject_name.clone(),
            "requireScaleRevealTransformOrigin",
            tag,
            "Scaled menu/listbox omits an explicit `origin-*` or `transformOrigin`.".to_string(),
            loc,
            span,
            None,
        );
    }

    // 12. Additional single-element and page-level design checks
    check_extended_design_patterns(
        semantic,
        node_id,
        jsx_el,
        tag,
        tokens,
        unvariant_tokens,
        trimmed_text,
        font_size,
        subject_name,
        const_strings,
        kicker_candidates,
        loc,
        span,
        line_starts,
        sites,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates extended typography, surface, motion, and page-composition design rules in one pass"
)]
fn check_extended_design_patterns(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    tag: &str,
    tokens: &[&str],
    unvariant_tokens: &[&str],
    trimmed_text: &str,
    font_size: Option<f64>,
    subject_name: &Option<String>,
    const_strings: &HashMap<SymbolId, String>,
    kicker_candidates: &mut Vec<(SourceLoc, ByteSpan)>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;

    // `no-all-caps-body-text`
    if matches!(tag, "p" | "blockquote" | "li" | "dd" | "figcaption" | "td")
        && trimmed_text.len() >= 48
        && (unvariant_tokens.contains(&"uppercase")
            || get_style_prop_str(opening, "textTransform", semantic, const_strings).as_deref()
                == Some("uppercase"))
    {
        push_design_site(
            sites,
            RuleId::NoAllCapsBodyText,
            subject_name.clone(),
            "noAllCapsBodyText",
            tag,
            "Long body copy is set in all caps, reducing reading speed.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-arbitrary-px-font-size`
    if let Some(px_tok) = unvariant_tokens
        .iter()
        .find(|u| u.starts_with("text-[") && u.contains("px]") && !u.starts_with("text-[0px]"))
    {
        push_design_site(
            sites,
            RuleId::NoArbitraryPxFontSize,
            subject_name.clone(),
            "noArbitraryPxFontSize",
            px_tok,
            format!(
                "`{px_tok}` uses pixels instead of `rem` and ignores user font-size preferences."
            ),
            loc,
            span,
            None,
        );
    }

    // `no-auto-scrolling-content`
    if (tag.starts_with("motion.") || tag.starts_with("m."))
        && find_attr(&opening.attributes, "animate")
            .is_some_and(|a| a.span.source_text(semantic.source_text()).contains("x:"))
        && find_attr(&opening.attributes, "transition").is_some_and(|a| {
            a.span
                .source_text(semantic.source_text())
                .contains("Infinity")
        })
    {
        push_design_site(
            sites,
            RuleId::NoAutoScrollingContent,
            subject_name.clone(),
            "noAutoScrollingContent",
            tag,
            "Content auto-scrolls infinitely without a pause control.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-clipped-overlay`
    if unvariant_tokens.contains(&"absolute")
        && find_attr_ignore_case(&opening.attributes, "role")
            .and_then(|a| get_attr_static_str(semantic, a, const_strings))
            .is_some_and(|r| matches!(r.as_str(), "dialog" | "listbox" | "menu" | "tooltip"))
        && has_ancestor_with_class(semantic, node_id, const_strings, |u| {
            matches!(u, "overflow-hidden" | "overflow-clip")
        })
    {
        push_design_site(
            sites,
            RuleId::NoClippedOverlay,
            subject_name.clone(),
            "noClippedOverlay",
            tag,
            "Positioned overlay sits inside an `overflow-hidden` ancestor and can be clipped."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-decorative-blur-orb`
    if matches!(tag, "div" | "span")
        && trimmed_text.is_empty()
        && unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "absolute" | "fixed"))
        && unvariant_tokens.contains(&"rounded-full")
        && unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "blur-2xl" | "blur-3xl") || u.starts_with("blur-["))
        && unvariant_tokens.iter().any(|u| u.starts_with("bg-"))
    {
        push_design_site(
            sites,
            RuleId::NoDecorativeBlurOrb,
            subject_name.clone(),
            "noDecorativeBlurOrb",
            tag,
            "Empty positioned blurred color circle acts as generic decorative scaffolding."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-empty-card-shell`
    if matches!(tag, "article" | "aside" | "section")
        && jsx_el.children.is_empty()
        && is_tailwind_card_tokens(unvariant_tokens)
    {
        push_design_site(
            sites,
            RuleId::NoEmptyCardShell,
            subject_name.clone(),
            "noEmptyCardShell",
            tag,
            "Empty semantic container renders a padded card shell without content.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-fixed-inside-transformed-ancestor`
    if (unvariant_tokens.contains(&"fixed")
        || get_style_prop_str(opening, "position", semantic, const_strings).as_deref()
            == Some("fixed"))
        && has_ancestor_with_class(semantic, node_id, const_strings, |u| {
            u.starts_with("scale-")
                || u.starts_with("translate-")
                || u.starts_with("rotate-")
                || u == "transform"
        })
    {
        push_design_site(
            sites,
            RuleId::NoFixedInsideTransformedAncestor,
            subject_name.clone(),
            "noFixedInsideTransformedAncestor",
            tag,
            "Fixed element sits inside a transformed ancestor and will not attach to the viewport."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-focus-in-animation-completion-handler`
    for handler_name in ["onAnimationEnd", "onTransitionEnd"] {
        if let Some(h_attr) = find_attr(&opening.attributes, handler_name)
            && h_attr
                .span
                .source_text(semantic.source_text())
                .contains(".focus(")
        {
            push_design_site(
                sites,
                RuleId::NoFocusInAnimationCompletionHandler,
                subject_name.clone(),
                "noFocusInAnimationCompletionHandler",
                handler_name,
                "Moving focus inside an animation completion handler fails when animations are disabled or canceled.".to_string(),
                loc_from_line_starts(line_starts, h_attr.span.start),
                ByteSpan {
                    start: h_attr.span.start,
                    end: h_attr.span.end,
                },
                None,
            );
        }
    }

    // `no-generic-purple-blue-icon-gradient`
    if unvariant_tokens.iter().any(|u| {
        u.starts_with("from-purple-")
            || u.starts_with("from-violet-")
            || u.starts_with("from-indigo-")
    }) && unvariant_tokens
        .iter()
        .any(|u| u.starts_with("to-blue-") || u.starts_with("to-cyan-") || u.starts_with("to-sky-"))
        && unvariant_tokens
            .iter()
            .any(|u| parse_tailwind_size_px(u).is_some_and(|px| px <= 64.0))
    {
        push_design_site(
            sites,
            RuleId::NoGenericPurpleBlueIconGradient,
            subject_name.clone(),
            "noGenericPurpleBlueIconGradient",
            tag,
            "Compact icon tile uses a generic purple-to-blue gradient.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-gray-on-colored-background`
    if unvariant_tokens.iter().any(|u| {
        u.starts_with("text-gray-") || u.starts_with("text-slate-") || u.starts_with("text-zinc-")
    }) && unvariant_tokens.iter().any(|u| {
        u.starts_with("bg-blue-")
            || u.starts_with("bg-indigo-")
            || u.starts_with("bg-purple-")
            || u.starts_with("bg-red-")
            || u.starts_with("bg-green-")
    }) {
        push_design_site(
            sites,
            RuleId::NoGrayOnColoredBackground,
            subject_name.clone(),
            "noGrayOnColoredBackground",
            tag,
            "Gray text on a saturated colored background looks washed out.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-hairline-border-wide-shadow` (Tailwind)
    if unvariant_tokens
        .iter()
        .any(|u| matches!(*u, "border" | "border-1" | "border-px"))
        && unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "shadow-xl" | "shadow-2xl"))
    {
        push_design_site(
            sites,
            RuleId::NoHairlineBorderWideShadow,
            subject_name.clone(),
            "noHairlineBorderWideShadow",
            tag,
            "Surface combines a hairline border with a wide diffuse shadow.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-image-hover-transform`
    if tag == "img"
        && tokens.iter().any(|t| {
            t.starts_with("hover:scale-")
                || t.starts_with("hover:rotate-")
                || t.starts_with("group-hover:scale-")
        })
    {
        push_design_site(
            sites,
            RuleId::NoImageHoverTransform,
            subject_name.clone(),
            "noImageHoverTransform",
            "img",
            "Image scales or rotates on hover.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-inert-pointer-affordance`
    if matches!(tag, "article" | "div" | "section" | "span" | "p")
        && unvariant_tokens.contains(&"cursor-pointer")
        && !opening.attributes.iter().any(|item| {
            item.as_attribute()
                .and_then(|a| a.name.as_identifier())
                .is_some_and(|id| {
                    id.name.starts_with("on") || id.name == "role" || id.name == "tabIndex"
                })
        })
    {
        push_design_site(
            sites,
            RuleId::NoInertPointerAffordance,
            subject_name.clone(),
            "noInertPointerAffordance",
            tag,
            "`cursor-pointer` is applied to a non-interactive element with no click handler."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-inert-sticky-position`
    let is_sticky = unvariant_tokens.contains(&"sticky")
        || get_style_prop_str(opening, "position", semantic, const_strings).as_deref()
            == Some("sticky");
    let has_inset = unvariant_tokens.iter().any(|u| {
        (u.starts_with("top-")
            || u.starts_with("bottom-")
            || u.starts_with("left-")
            || u.starts_with("right-")
            || u.starts_with("inset-"))
            && !u.ends_with("-auto")
    }) || ["top", "bottom", "left", "right", "inset"].iter().any(|p| {
        get_style_prop_str(opening, p, semantic, const_strings).is_some()
            || get_style_prop_number(opening, p).is_some()
    });
    if is_sticky && !has_inset {
        push_design_site(
            sites,
            RuleId::NoInertStickyPosition,
            subject_name.clone(),
            "noInertStickyPosition",
            tag,
            "Sticky element has no `top`/`bottom`/`inset` offset and will not stick.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-inline-bounce-easing` (Tailwind `animate-bounce`)
    if unvariant_tokens.contains(&"animate-bounce")
        && !unvariant_tokens.iter().any(|u| u.contains("delay"))
    {
        push_design_site(
            sites,
            RuleId::NoInlineBounceEasing,
            subject_name.clone(),
            "noInlineBounceEasing",
            tag,
            "`animate-bounce` uses bouncy easing; prefer smooth curves for UI elements."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-invisible-focus-control`
    if matches!(tag, "input" | "select" | "textarea" | "button")
        && unvariant_tokens.contains(&"opacity-0")
        && !tokens.iter().any(|t| {
            t.starts_with("focus:") || t.starts_with("focus-visible:") || t.starts_with("peer-")
        })
        && !has_ancestor_with_class(semantic, node_id, const_strings, |t| {
            t.starts_with("focus-within:")
        })
    {
        push_design_site(
            sites,
            RuleId::NoInvisibleFocusControl,
            subject_name.clone(),
            "noInvisibleFocusControl",
            tag,
            "Invisible native control (`opacity-0`) lacks a visible focus or `focus-within:` indicator.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-layout-shifting-interaction-state`
    if let Some(shift_tok) = tokens.iter().find(|t| {
        (t.starts_with("hover:") || t.starts_with("focus:") || t.starts_with("active:")) && {
            let u = t.rsplit(':').next().unwrap_or(t);
            u.starts_with("p-")
                || u.starts_with("px-")
                || u.starts_with("py-")
                || u.starts_with("m-")
                || u.starts_with("w-")
                || u.starts_with("h-")
        }
    }) {
        push_design_site(
            sites,
            RuleId::NoLayoutShiftingInteractionState,
            subject_name.clone(),
            "noLayoutShiftingInteractionState",
            shift_tok,
            format!("`{shift_tok}` changes layout geometry on interaction."),
            loc,
            span,
            None,
        );
    }

    // `no-nested-card-surface`
    if is_tailwind_card_tokens(unvariant_tokens)
        && unvariant_tokens.iter().any(|u| u.starts_with("p-"))
        && has_card_ancestor(semantic, node_id, const_strings)
    {
        push_design_site(
            sites,
            RuleId::NoNestedCardSurface,
            subject_name.clone(),
            "noNestedCardSurface",
            tag,
            "Card surface is nested inside another card.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-overloaded-hover-state`
    let mut hover_groups: HashSet<&str> = HashSet::new();
    for &t in tokens {
        if let Some(u) = t.strip_prefix("hover:") {
            if u.starts_with("-translate") || u.starts_with("translate") || u.starts_with("scale") {
                hover_groups.insert("transform");
            } else if u.starts_with("bg-") || u.starts_with("text-") || u.starts_with("border-") {
                hover_groups.insert("color");
            } else if u.starts_with("shadow") {
                hover_groups.insert("shadow");
            }
        }
    }
    if hover_groups.len() >= 3 {
        push_design_site(
            sites,
            RuleId::NoOverloadedHoverState,
            subject_name.clone(),
            "noOverloadedHoverState",
            tag,
            "Hover state stacks 3+ distinct visual effect groups.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-overwide-text-measure`
    if matches!(tag, "p" | "blockquote" | "li" | "dd" | "figcaption") {
        let overwide = unvariant_tokens.iter().any(|u| {
            u.strip_prefix("max-w-[")
                .or_else(|| u.strip_prefix("w-["))
                .and_then(|s| s.strip_suffix("ch]"))
                .and_then(|n| n.parse::<f64>().ok())
                .is_some_and(|ch| ch > 80.0)
        }) || ["maxWidth", "width"].iter().any(|p| {
            get_style_prop_str(opening, p, semantic, const_strings)
                .and_then(|s| {
                    s.trim()
                        .strip_suffix("ch")
                        .and_then(|n| n.parse::<f64>().ok())
                })
                .is_some_and(|ch| ch > 80.0)
        });
        if overwide {
            push_design_site(
                sites,
                RuleId::NoOverwideTextMeasure,
                subject_name.clone(),
                "noOverwideTextMeasure",
                tag,
                "Text measure exceeds 80ch; constrain long-form text to 60–75ch.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // `no-pill-navigation-count`
    if matches!(tag, "span" | "small")
        && !trimmed_text.is_empty()
        && trimmed_text.bytes().all(|b| b.is_ascii_digit())
        && unvariant_tokens.contains(&"rounded-full")
        && unvariant_tokens.iter().any(|u| u.starts_with("px-"))
        && has_enclosing_nav_or_aside(semantic, node_id)
    {
        push_design_site(
            sites,
            RuleId::NoPillNavigationCount,
            subject_name.clone(),
            "noPillNavigationCount",
            tag,
            "Navigation count is styled as a pill badge instead of plain tabular text.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-pointer-disabled-enabled-control`
    if matches!(tag, "button" | "input" | "select" | "textarea" | "a")
        && (unvariant_tokens.contains(&"pointer-events-none")
            || get_style_prop_str(opening, "pointerEvents", semantic, const_strings).as_deref()
                == Some("none"))
        && find_attr_ignore_case(&opening.attributes, "disabled").is_none()
        && find_attr_ignore_case(&opening.attributes, "aria-disabled").is_none()
    {
        push_design_site(
            sites,
            RuleId::NoPointerDisabledEnabledControl,
            subject_name.clone(),
            "noPointerDisabledEnabledControl",
            tag,
            "Enabled control has `pointer-events-none` without `disabled` semantics.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-pure-black-shadow` (Tailwind)
    if unvariant_tokens
        .iter()
        .any(|u| *u == "shadow-black" || u.starts_with("shadow-black/"))
    {
        push_design_site(
            sites,
            RuleId::NoPureBlackShadow,
            subject_name.clone(),
            "noPureBlackShadow",
            tag,
            "Surface uses a pure-black shadow.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-redundant-title-tooltip`
    if matches!(tag, "button" | "a" | "summary")
        && !trimmed_text.is_empty()
        && let Some(title_attr) = find_attr_ignore_case(&opening.attributes, "title")
        && let Some(title_val) = get_attr_static_str(semantic, title_attr, const_strings)
        && title_val.trim().eq_ignore_ascii_case(trimmed_text)
        && !unvariant_tokens
            .iter()
            .any(|u| *u == "truncate" || *u == "text-ellipsis" || u.starts_with("line-clamp-"))
    {
        push_design_site(
            sites,
            RuleId::NoRedundantTitleTooltip,
            subject_name.clone(),
            "noRedundantTitleTooltip",
            "title",
            "Title tooltip repeats the control's visible text.".to_string(),
            loc_from_line_starts(line_starts, title_attr.span.start),
            ByteSpan {
                start: title_attr.span.start,
                end: title_attr.span.end,
            },
            None,
        );
    }

    // `no-svg-currentcolor-with-fill-class`
    if tag == "svg" {
        for paint in ["fill", "stroke"] {
            if let Some(p_attr) = find_attr(&opening.attributes, paint)
                && get_attr_static_str(semantic, p_attr, const_strings)
                    .is_some_and(|v| v.eq_ignore_ascii_case("currentColor"))
                && unvariant_tokens.iter().any(|u| {
                    u.starts_with(&format!("{paint}-"))
                        && *u != format!("{paint}-current")
                        && *u != format!("{paint}-none")
                })
            {
                push_design_site(
                    sites,
                    RuleId::NoSvgCurrentcolorWithFillClass,
                    subject_name.clone(),
                    "noSvgCurrentcolorWithFillClass",
                    paint,
                    format!(
                        "`{paint}=\"currentColor\"` conflicts with a `{paint}-*` color utility class."
                    ),
                    loc_from_line_starts(line_starts, p_attr.span.start),
                    ByteSpan {
                        start: p_attr.span.start,
                        end: p_attr.span.end,
                    },
                    None,
                );
            }
        }
    }

    // `no-symmetric-text-button-padding`
    if tag == "button"
        && !trimmed_text.is_empty()
        && unvariant_tokens.iter().any(|u| u.starts_with("p-"))
        && !unvariant_tokens.iter().any(|u| {
            u.starts_with("px-")
                || u.starts_with("py-")
                || u.starts_with("pl-")
                || u.starts_with("pr-")
        })
    {
        push_design_site(
            sites,
            RuleId::NoSymmetricTextButtonPadding,
            subject_name.clone(),
            "noSymmetricTextButtonPadding",
            "button",
            "Text button uses equal padding on all sides; give horizontal axis more padding."
                .to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-tailwind-layout-transition`
    for &u in unvariant_tokens {
        if let Some(inner) = u
            .strip_prefix("transition-[")
            .and_then(|s| s.strip_suffix(']'))
            && inner
                .split(',')
                .any(|p| LAYOUT_TRANSITION_PROPS.contains(&p.trim()))
        {
            push_design_site(
                sites,
                RuleId::NoTailwindLayoutTransition,
                subject_name.clone(),
                "noTailwindLayoutTransition",
                u,
                format!("`{u}` animates a layout property."),
                loc,
                span,
                None,
            );
        }
    }

    // `no-tight-all-caps-heading`, `no-tight-body-leading`, `no-tight-display-tracking`
    if matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
        if trimmed_text.len() >= 24
            && unvariant_tokens.contains(&"uppercase")
            && unvariant_tokens.contains(&"leading-none")
        {
            push_design_site(
                sites,
                RuleId::NoTightAllCapsHeading,
                subject_name.clone(),
                "noTightAllCapsHeading",
                tag,
                "Long all-caps heading uses `leading-none`, risking line collisions.".to_string(),
                loc,
                span,
                None,
            );
        }
        if matches!(tag, "h1" | "h2" | "h3")
            && !trimmed_text.is_empty()
            && unvariant_tokens.contains(&"tracking-tighter")
        {
            push_design_site(
                sites,
                RuleId::NoTightDisplayTracking,
                subject_name.clone(),
                "noTightDisplayTracking",
                tag,
                "Display heading uses `tracking-tighter`.".to_string(),
                loc,
                span,
                None,
            );
        }
    }
    if matches!(tag, "p" | "blockquote" | "li" | "dd" | "figcaption" | "td")
        && trimmed_text.len() >= 48
        && (unvariant_tokens
            .iter()
            .any(|u| matches!(*u, "leading-none" | "leading-tight"))
            || get_style_prop_number(opening, "lineHeight").is_some_and(|lh| lh > 0.0 && lh < 1.3))
    {
        push_design_site(
            sites,
            RuleId::NoTightBodyLeading,
            subject_name.clone(),
            "noTightBodyLeading",
            tag,
            "Body copy has cramped line-height (< 1.3).".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-tiny-uppercase-tracked-label`, `no-uppercase-mono-label`, `no-uppercase-tracked-navigation-label`
    if !trimmed_text.is_empty()
        && trimmed_text.len() <= 32
        && unvariant_tokens.contains(&"uppercase")
        && unvariant_tokens.iter().any(|u| u.starts_with("tracking-"))
    {
        if font_size.is_some_and(|px| px > 0.0 && px <= 11.0) {
            push_design_site(
                sites,
                RuleId::NoTinyUppercaseTrackedLabel,
                subject_name.clone(),
                "noTinyUppercaseTrackedLabel",
                tag,
                "Tiny label (<= 11px) combines uppercase and letter-spacing.".to_string(),
                loc,
                span,
                None,
            );
        }
        if unvariant_tokens.contains(&"font-mono") {
            push_design_site(
                sites,
                RuleId::NoUppercaseMonoLabel,
                subject_name.clone(),
                "noUppercaseMonoLabel",
                tag,
                "Short label combines `font-mono`, `uppercase`, and tracking.".to_string(),
                loc,
                span,
                None,
            );
        }
        if has_enclosing_nav_or_aside(semantic, node_id) {
            push_design_site(
                sites,
                RuleId::NoUppercaseTrackedNavigationLabel,
                subject_name.clone(),
                "noUppercaseTrackedNavigationLabel",
                tag,
                "Navigation label uses uppercase tracking.".to_string(),
                loc,
                span,
                None,
            );
        }
        kicker_candidates.push((loc, span));
    }

    // `no-transitioned-composite-widget-state` & `no-transitioned-focus-ring`
    if unvariant_tokens.contains(&"transition-colors")
        && tokens
            .iter()
            .any(|t| t.starts_with("aria-selected:") || t.starts_with("data-[state=active]:"))
    {
        push_design_site(
            sites,
            RuleId::NoTransitionedCompositeWidgetState,
            subject_name.clone(),
            "noTransitionedCompositeWidgetState",
            tag,
            "Composite widget item delays selection color feedback with `transition-colors`."
                .to_string(),
            loc,
            span,
            None,
        );
    }
    if unvariant_tokens.iter().any(|u| {
        matches!(
            *u,
            "transition-shadow" | "transition-[box-shadow]" | "transition-[outline]"
        )
    }) && tokens
        .iter()
        .any(|t| t.starts_with("focus-visible:ring") || t.starts_with("focus-visible:outline"))
    {
        push_design_site(
            sites,
            RuleId::NoTransitionedFocusRing,
            subject_name.clone(),
            "noTransitionedFocusRing",
            tag,
            "Transition utility delays the `focus-visible:` indicator.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-shape-assembled-illustration`
    if tag == "svg" {
        let mut shape_count = 0;
        count_svg_primitives(jsx_el, &mut shape_count);
        if shape_count >= 8 {
            push_design_site(
                sites,
                RuleId::NoShapeAssembledIllustration,
                subject_name.clone(),
                "noShapeAssembledIllustration",
                "svg",
                "Large SVG illustration is assembled from 8+ primitive shapes.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // `no-repeated-placeholder-navigation`
    if matches!(tag, "nav" | "aside") {
        let mut placeholder_links = 0;
        count_placeholder_anchors(jsx_el, semantic, const_strings, &mut placeholder_links);
        if placeholder_links >= 2 {
            push_design_site(
                sites,
                RuleId::NoRepeatedPlaceholderNavigation,
                subject_name.clone(),
                "noRepeatedPlaceholderNavigation",
                tag,
                "Navigation contains multiple `<a href=\"#\">` placeholder links.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // `no-fake-browser-chrome`
    if unvariant_tokens.contains(&"overflow-hidden")
        && unvariant_tokens.iter().any(|u| u.starts_with("rounded"))
        && unvariant_tokens.iter().any(|u| u.starts_with("border"))
        && has_traffic_light_dots(jsx_el, semantic, const_strings)
    {
        push_design_site(
            sites,
            RuleId::NoFakeBrowserChrome,
            subject_name.clone(),
            "noFakeBrowserChrome",
            tag,
            "Preview redraws decorative traffic-light browser chrome.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-uniform-feature-card-grid`
    if matches!(tag, "div" | "section") && unvariant_tokens.contains(&"grid") {
        let direct_cards: Vec<&JSXElement<'_>> = jsx_el
            .children
            .iter()
            .filter_map(|c| {
                if let JSXChild::Element(el) = c {
                    Some(el.as_ref())
                } else {
                    None
                }
            })
            .collect();
        if direct_cards.len() >= 3
            && direct_cards.iter().all(|card| {
                let c_str = get_class_name_str(&card.opening_element, semantic, const_strings)
                    .unwrap_or_default();
                let c_toks: Vec<&str> = c_str.split_whitespace().collect();
                is_tailwind_card_tokens(&c_toks)
                    && subtree_has_tag_matching(card, |t| matches!(t, "h2" | "h3" | "h4"))
                    && subtree_has_tag_matching(card, |t| t == "p")
            })
        {
            push_design_site(
                sites,
                RuleId::NoUniformFeatureCardGrid,
                subject_name.clone(),
                "noUniformFeatureCardGrid",
                tag,
                "Feature grid repeats the same rounded card-and-heading recipe across all items."
                    .to_string(),
                loc,
                span,
                None,
            );
        }
    }
    // `no-pure-black-background`
    let has_pure_black_bg = unvariant_tokens
        .iter()
        .any(|u| matches!(*u, "bg-black" | "bg-[#000]" | "bg-[#000000]"))
        || ["backgroundColor", "background"].iter().any(|prop| {
            get_style_prop_str(opening, prop, semantic, const_strings).is_some_and(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "#000" | "#000000" | "black" | "rgb(0, 0, 0)" | "rgb(0,0,0)"
                )
            })
        });
    if has_pure_black_bg {
        push_design_site(
            sites,
            RuleId::NoPureBlackBackground,
            subject_name.clone(),
            "noPureBlackBackground",
            tag,
            "Surface uses a pure-black background; prefer a tinted dark neutral token.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-italic-serif-display-heading`
    if matches!(tag, "h1" | "h2") {
        let is_serif = unvariant_tokens.contains(&"font-serif")
            || get_style_prop_str(opening, "fontFamily", semantic, const_strings)
                .is_some_and(|ff| ff.to_ascii_lowercase().contains("serif") && !ff.to_ascii_lowercase().contains("sans-serif"));
        let is_italic = unvariant_tokens.contains(&"italic")
            || get_style_prop_str(opening, "fontStyle", semantic, const_strings).as_deref()
                == Some("italic")
            || subtree_has_tag_matching(jsx_el, |t| matches!(t, "em" | "i"));
        if is_serif && is_italic {
            push_design_site(
                sites,
                RuleId::NoItalicSerifDisplayHeading,
                subject_name.clone(),
                "noItalicSerifDisplayHeading",
                tag,
                "Display heading combines italic and serif styling.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // `no-full-viewport-centered-hero`
    if matches!(tag, "section" | "header" | "div")
        && unvariant_tokens.iter().any(|u| {
            matches!(
                *u,
                "min-h-screen" | "h-screen" | "min-h-dvh" | "h-dvh" | "min-h-[100vh]" | "h-[100vh]"
            )
        })
        && unvariant_tokens.contains(&"items-center")
        && unvariant_tokens.contains(&"justify-center")
        && (unvariant_tokens.contains(&"text-center") || has_descendant_text_center(jsx_el, semantic, const_strings))
        && subtree_has_tag_matching(jsx_el, |t| t == "h1")
    {
        push_design_site(
            sites,
            RuleId::NoFullViewportCenteredHero,
            subject_name.clone(),
            "noFullViewportCenteredHero",
            tag,
            "Hero uses a full-viewport centered template.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-hero-eyebrow-chip` & `no-numbered-section-markers` & `no-icon-tile-heading-stack`
    let direct_el_children: Vec<&JSXElement<'_>> = jsx_el
        .children
        .iter()
        .filter_map(|c| {
            if let JSXChild::Element(el) = c {
                Some(el.as_ref())
            } else {
                None
            }
        })
        .collect();
    if direct_el_children.len() >= 2 {
        let first_el = direct_el_children[0];
        let second_el = direct_el_children[1];
        let first_tag = get_jsx_tag_name(&first_el.opening_element.name);
        let second_tag = get_jsx_tag_name(&second_el.opening_element.name);
        let first_cls =
            get_class_name_str(&first_el.opening_element, semantic, const_strings).unwrap_or_default();
        let first_toks: Vec<&str> = first_cls
            .split_whitespace()
            .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
            .collect();
        let first_txt = collect_all_static_text(first_el);
        let first_trimmed = first_txt.trim();

        if second_tag == "h1"
            && !first_trimmed.is_empty()
            && first_trimmed.len() <= 40
            && (first_toks.contains(&"rounded-full")
                || (first_toks.contains(&"uppercase")
                    && first_toks.iter().any(|u| u.starts_with("border") || u.starts_with("bg-"))))
        {
            push_design_site(
                sites,
                RuleId::NoHeroEyebrowChip,
                subject_name.clone(),
                "noHeroEyebrowChip",
                &first_tag,
                "Hero places a decorative eyebrow chip above its primary heading.".to_string(),
                loc_from_line_starts(line_starts, first_el.opening_element.span.start),
                ByteSpan {
                    start: first_el.opening_element.span.start,
                    end: first_el.opening_element.span.end,
                },
                None,
            );
        }

        if matches!(second_tag.as_str(), "h2" | "h3") && is_numbered_section_marker_text(first_trimmed) {
            push_design_site(
                sites,
                RuleId::NoNumberedSectionMarkers,
                subject_name.clone(),
                "noNumberedSectionMarkers",
                &first_tag,
                "Section uses a decorative numeric marker before its heading.".to_string(),
                loc_from_line_starts(line_starts, first_el.opening_element.span.start),
                ByteSpan {
                    start: first_el.opening_element.span.start,
                    end: first_el.opening_element.span.end,
                },
                None,
            );
        }

        if is_tailwind_card_tokens(unvariant_tokens)
            && matches!(second_tag.as_str(), "h2" | "h3" | "h4")
            && is_icon_tile_element(first_el, &first_toks)
        {
            push_design_site(
                sites,
                RuleId::NoIconTileHeadingStack,
                subject_name.clone(),
                "noIconTileHeadingStack",
                tag,
                "Card stacks a boxed icon tile above its heading.".to_string(),
                loc,
                span,
                None,
            );
        }
    }

    // Page-root checks on `<main>` or `<article>`
    if matches!(tag, "main" | "article") {
        check_page_root_design_rules(
            jsx_el,
            tag,
            trimmed_text,
            semantic,
            const_strings,
            subject_name,
            loc,
            span,
            line_starts,
            sites,
        );
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates page-level composition and copy design rules on <main>/<article> roots"
)]
fn check_page_root_design_rules(
    jsx_el: &JSXElement<'_>,
    tag: &str,
    trimmed_text: &str,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    subject_name: &Option<String>,
    loc: SourceLoc,
    span: ByteSpan,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let lower_text = trimmed_text.to_ascii_lowercase();
    let root_opening = &jsx_el.opening_element;
    let root_cls = get_class_name_str(root_opening, semantic, const_strings).unwrap_or_default();
    let root_toks: Vec<&str> = root_cls
        .split_whitespace()
        .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
        .collect();

    // `no-common-root-font`
    let has_common_font = root_toks.contains(&"font-sans")
        || get_style_prop_str(root_opening, "fontFamily", semantic, const_strings).is_some_and(
            |ff| {
                let primary = ff
                    .split(',')
                    .next()
                    .unwrap_or(&ff)
                    .trim()
                    .trim_matches(['"', '\''])
                    .to_ascii_lowercase();
                matches!(
                    primary.as_str(),
                    "inter"
                        | "roboto"
                        | "arial"
                        | "helvetica"
                        | "system-ui"
                        | "sans-serif"
                        | "open sans"
                        | "segoe ui"
                )
            },
        );
    if has_common_font {
        push_design_site(
            sites,
            RuleId::NoCommonRootFont,
            subject_name.clone(),
            "noCommonRootFont",
            tag,
            "Page root uses a generic default font choice.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-default-purple-page-gradient`
    let has_purple_page_gradient = (root_toks
        .iter()
        .any(|u| u.starts_with("bg-gradient-") || u.starts_with("bg-linear-"))
        && root_toks.iter().any(|u| {
            u.starts_with("from-purple-")
                || u.starts_with("from-violet-")
                || u.starts_with("from-indigo-")
                || u.starts_with("via-purple-")
                || u.starts_with("to-purple-")
                || u.starts_with("to-violet-")
                || u.starts_with("to-indigo-")
        }))
        || ["background", "backgroundImage"].iter().any(|p| {
            get_style_prop_str(root_opening, p, semantic, const_strings).is_some_and(|v| {
                let lower = v.to_ascii_lowercase();
                lower.contains("gradient(")
                    && (lower.contains("purple")
                        || lower.contains("violet")
                        || lower.contains("indigo")
                        || lower.contains("#7c3aed")
                        || lower.contains("#6366f1")
                        || lower.contains("#8b5cf6"))
            })
        });
    if has_purple_page_gradient {
        push_design_site(
            sites,
            RuleId::NoDefaultPurplePageGradient,
            subject_name.clone(),
            "noDefaultPurplePageGradient",
            tag,
            "Page root uses a default purple-spectrum gradient.".to_string(),
            loc,
            span,
            None,
        );
    }

    // `no-default-warm-page-surface`
    let has_warm_page_surface = root_toks.iter().any(|u| {
        matches!(
            *u,
            "bg-amber-50"
                | "bg-orange-50"
                | "bg-yellow-50"
                | "bg-stone-50"
                | "bg-[#faf8f5]"
                | "bg-[#fdfbf7]"
                | "bg-[#f9f6f0]"
        )
    }) || ["backgroundColor", "background"].iter().any(|p| {
        get_style_prop_str(root_opening, p, semantic, const_strings).is_some_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "#faf8f5" | "#fdfbf7" | "#f9f6f0" | "#fffbeb" | "#fefce8" | "#fafaf9"
            )
        })
    });
    if has_warm_page_surface {
        push_design_site(
            sites,
            RuleId::NoDefaultWarmPageSurface,
            subject_name.clone(),
            "noDefaultWarmPageSurface",
            tag,
            "Page defaults to a warm off-white surface.".to_string(),
            loc,
            span,
            None,
        );
    }

    if GENERIC_MARKETING_PHRASES
        .iter()
        .any(|phrase| lower_text.contains(phrase))
    {
        push_design_site(
            sites,
            RuleId::NoGenericMarketingCopy,
            subject_name.clone(),
            "noGenericMarketingCopy",
            tag,
            "Page uses generic marketing copy.".to_string(),
            loc,
            span,
            None,
        );
    }

    if lower_text.contains("jane doe")
        || lower_text.contains("john smith")
        || lower_text.contains("example user")
    {
        push_design_site(
            sites,
            RuleId::NoPlaceholderPersonaCopy,
            subject_name.clone(),
            "noPlaceholderPersonaCopy",
            tag,
            "Page renders a generic placeholder persona (`Jane Doe` / `John Smith`).".to_string(),
            loc,
            span,
            None,
        );
    }

    let contrast_hits = lower_text.matches("not just ").count()
        + lower_text.matches("no busywork").count()
        + lower_text.matches("not a ").count();
    if contrast_hits >= 3 {
        push_design_site(
            sites,
            RuleId::NoManufacturedContrastCopy,
            subject_name.clone(),
            "noManufacturedContrastCopy",
            tag,
            "Page repeatedly uses manufactured contrast copy (`Not X. It is Y.`).".to_string(),
            loc,
            span,
            None,
        );
    }

    let mut stats = PageSubtreeStats::default();
    collect_page_subtree_stats(jsx_el, semantic, const_strings, line_starts, &mut stats);

    if stats.card_count >= 6 {
        push_design_site(
            sites,
            RuleId::NoExcessiveCardSurfaces,
            subject_name.clone(),
            "noExcessiveCardSurfaces",
            tag,
            format!("Page boxes {} groups into cards.", stats.card_count),
            loc,
            span,
            None,
        );
    }
    if stats.centered_paragraph_count >= 3 {
        push_design_site(
            sites,
            RuleId::NoExcessiveCenteredCopy,
            subject_name.clone(),
            "noExcessiveCenteredCopy",
            tag,
            "Page centers 3+ substantial body-copy paragraphs.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.font_families.len() >= 4 {
        push_design_site(
            sites,
            RuleId::NoExcessiveFontFamilies,
            subject_name.clone(),
            "noExcessiveFontFamilies",
            tag,
            "Page mixes 4+ distinct font families.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.pill_count >= 5 {
        push_design_site(
            sites,
            RuleId::NoExcessivePillTreatment,
            subject_name.clone(),
            "noExcessivePillTreatment",
            tag,
            "Page overuses pill-shaped (`rounded-full`) treatments.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.emoji_tile_count >= 3 {
        push_design_site(
            sites,
            RuleId::NoRepeatedEmojiTiles,
            subject_name.clone(),
            "noRepeatedEmojiTiles",
            tag,
            "Page repeats boxed emoji tiles as feature icons.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.glass_surface_count >= 3 {
        push_design_site(
            sites,
            RuleId::NoRepeatedGlassSurfaces,
            subject_name.clone(),
            "noRepeatedGlassSurfaces",
            tag,
            "Page repeats blurred translucent glass surfaces.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats.hover_scale_sites.len() >= 3
        && let Some((hloc, hspan)) = stats.hover_scale_sites.first().copied()
    {
        push_design_site(
            sites,
            RuleId::NoRepeatedHoverScale,
            subject_name.clone(),
            "noRepeatedHoverScale",
            "hover:scale",
            "Hover scaling repeats across 3+ elements on the page.".to_string(),
            hloc,
            hspan,
            None,
        );
    }
    if stats.section_shell_count >= 3 {
        push_design_site(
            sites,
            RuleId::NoRepeatedSectionShells,
            subject_name.clone(),
            "noRepeatedSectionShells",
            tag,
            "Page repeats the same large-padding centered max-width section shell.".to_string(),
            loc,
            span,
            None,
        );
    }
    if stats
        .section_py_counts
        .values()
        .any(|&count| count >= 4 && stats.section_py_counts.len() == 1)
    {
        push_design_site(
            sites,
            RuleId::NoMonotonousPageSpacing,
            subject_name.clone(),
            "noMonotonousPageSpacing",
            tag,
            "Page repeats one vertical spacing value across all sections.".to_string(),
            loc,
            span,
            None,
        );
    }
}

fn check_tagged_template_design(
    semantic: &Semantic<'_>,
    tagged: &oxc_ast::ast::TaggedTemplateExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let tag_src = tagged.tag.span().source_text(semantic.source_text());
    if tag_src != "css" && !tag_src.starts_with("styled.") && !tag_src.starts_with("styled(") {
        return;
    }
    let raw_css: String = tagged
        .quasi
        .quasis
        .iter()
        .map(|q| q.value.raw.as_str())
        .collect::<Vec<_>>()
        .join("VAL");
    let mut seen_props: HashSet<String> = HashSet::new();
    for decl in raw_css.split(';') {
        let trimmed = decl.trim();
        if trimmed.contains('{') || trimmed.contains('}') {
            continue;
        }
        if let Some((prop, _)) = trimmed.split_once(':') {
            let p = prop.trim().to_ascii_lowercase();
            if !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
                && !seen_props.insert(p.clone())
            {
                let loc = loc_from_line_starts(line_starts, tagged.span.start);
                let span = ByteSpan {
                    start: tagged.span.start,
                    end: tagged.span.end,
                };
                push_design_site(
                    sites,
                    RuleId::StyledComponentsDuplicateCssPropertyInBlock,
                    subject_name.clone(),
                    "styledComponentsDuplicateCssPropertyInBlock",
                    &p,
                    format!("Duplicate CSS property `{p}` in styled-components block."),
                    loc,
                    span,
                    None,
                );
                break;
            }
        }
    }
}

// --- Helper functions ---

fn classify_icon_library_family(source: &str) -> Option<&str> {
    if source == "lucide-react" {
        Some("lucide")
    } else if source.starts_with("@heroicons/") {
        Some("heroicons")
    } else if source.starts_with("@radix-ui/react-icons") {
        Some("radix-icons")
    } else if source.starts_with("@tabler/icons") {
        Some("tabler")
    } else if source.starts_with("phosphor-react") || source.starts_with("@phosphor-icons/") {
        Some("phosphor")
    } else if source.starts_with("react-icons/") {
        Some(source)
    } else {
        None
    }
}

fn has_responsive_axis_prefix(tokens: &[&str], axis: &str) -> bool {
    let suffix = format!(":{axis}-");
    tokens.iter().any(|t| t.contains(&suffix))
}

fn collect_matching_axis_values(tokens: &[&str], prefix_a: &str, prefix_b: &str) -> Vec<String> {
    let mut a_vals: Vec<&str> = Vec::new();
    for &t in tokens {
        if let Some(val) = t.strip_prefix(prefix_a)
            && !val.is_empty()
        {
            a_vals.push(val);
        }
    }
    let mut matched = Vec::new();
    for &t in tokens {
        if let Some(val) = t.strip_prefix(prefix_b)
            && a_vals.contains(&val)
            && !matched.iter().any(|m: &String| m == val)
        {
            matched.push(val.to_string());
        }
    }
    matched
}

fn is_static_style_literal(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        Expression::UnaryExpression(u) => matches!(
            u.argument.without_parentheses(),
            Expression::NumericLiteral(_)
        ),
        _ => false,
    }
}

fn parse_px_or_rem(val: &str) -> Option<f64> {
    let t = val.trim().to_ascii_lowercase();
    if let Some(px) = t.strip_suffix("px") {
        px.parse::<f64>().ok()
    } else if let Some(rem) = t.strip_suffix("rem") {
        rem.parse::<f64>().ok().map(|v| v * 16.0)
    } else {
        t.parse::<f64>().ok()
    }
}

fn has_duration_over_1000ms(val: &str) -> bool {
    for tok in val.split(|c: char| c.is_whitespace() || c == ',') {
        if let Some(ms_str) = tok.strip_suffix("ms") {
            if ms_str.parse::<f64>().is_ok_and(|ms| ms > 1000.0) {
                return true;
            }
        } else if let Some(s_str) = tok.strip_suffix('s')
            && s_str.parse::<f64>().is_ok_and(|s| s > 1.0)
        {
            return true;
        }
    }
    false
}

fn parse_hex_or_rgb_color(val: &str) -> Option<(f64, f64, f64)> {
    let t = val.trim().to_ascii_lowercase();
    if let Some(hex) = t.strip_prefix('#') {
        if hex.len() == 3 {
            let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
            let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
            let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
            return Some((f64::from(r), f64::from(g), f64::from(b)));
        } else if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            return Some((f64::from(r), f64::from(g), f64::from(b)));
        }
    }
    if let Some(inner) = t
        .strip_prefix("rgb(")
        .or_else(|| t.strip_prefix("rgba("))
        .and_then(|s| s.strip_suffix(')'))
    {
        let nums: Vec<f64> = inner
            .split([',', ' ', '/'])
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<f64>().ok())
            .collect();
        if nums.len() >= 3 {
            return Some((nums[0], nums[1], nums[2]));
        }
    }
    None
}

fn wcag_contrast_ratio(fg: (f64, f64, f64), bg: (f64, f64, f64)) -> f64 {
    let lin = |c: f64| -> f64 {
        let n = c / 255.0;
        if n <= 0.03928 {
            n / 12.92
        } else {
            ((n + 0.055) / 1.055).powf(2.4)
        }
    };
    let lum = |(r, g, b): (f64, f64, f64)| 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
    let l1 = lum(fg);
    let l2 = lum(bg);
    let lighter = l1.max(l2);
    let darker = l1.min(l2);
    (lighter + 0.05) / (darker + 0.05)
}

fn collect_direct_button_label_text(jsx_el: &JSXElement<'_>) -> Option<String> {
    let mut out = String::new();
    for child in &jsx_el.children {
        match child {
            JSXChild::Text(t) => out.push_str(t.value.as_str()),
            JSXChild::ExpressionContainer(c) => {
                if let Some(Expression::StringLiteral(s)) = c.expression.as_expression()
                    && let Some(v) = s.value.as_str()
                {
                    out.push_str(v);
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let trimmed = out.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn normalize_button_label(s: &str) -> String {
    s.trim()
        .trim_end_matches(['.', '!', '?', '…'])
        .trim()
        .to_ascii_lowercase()
}

fn enclosing_form_has_previous_step_control(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(form_el) = semantic.nodes().kind(anc_id)
            && get_jsx_tag_name(&form_el.opening_element.name) == "form"
        {
            return subtree_has_previous_step_control(&form_el.children);
        }
    }
    false
}

fn subtree_has_previous_step_control(children: &[JSXChild<'_>]) -> bool {
    for child in children {
        match child {
            JSXChild::Element(el) => {
                let tag = get_jsx_tag_name(&el.opening_element.name);
                if matches!(tag.as_str(), "button" | "Button" | "a" | "Link")
                    && let Some(lbl) = collect_direct_button_label_text(el)
                    && matches!(normalize_button_label(&lbl).as_str(), "back" | "previous")
                {
                    return true;
                }
                if subtree_has_previous_step_control(&el.children) {
                    return true;
                }
            }
            JSXChild::Fragment(frag) if subtree_has_previous_step_control(&frag.children) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn is_inside_excluded_typography_element(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for id in std::iter::once(node_id).chain(semantic.nodes().ancestor_ids(node_id)) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(id) {
            let tag = get_jsx_tag_name(&el.opening_element.name).to_ascii_lowercase();
            if EXCLUDED_TYPOGRAPHY_TAGS.contains(&tag.as_str()) {
                return true;
            }
            if find_attr_ignore_case(&el.opening_element.attributes, "translate")
                .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                .is_some_and(|v| v.eq_ignore_ascii_case("no"))
            {
                return true;
            }
        }
    }
    false
}

fn has_word_three_period_ellipsis(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (idx, _) in text.match_indices("...") {
        if idx > 0 && bytes[idx - 1].is_ascii_alphanumeric() {
            return true;
        }
    }
    false
}

fn has_direct_visible_text(jsx_el: &JSXElement<'_>) -> bool {
    for child in &jsx_el.children {
        match child {
            JSXChild::Text(t) if !t.value.trim().is_empty() => return true,
            JSXChild::Element(el) => {
                let tag = get_jsx_tag_name(&el.opening_element.name);
                if tag != "svg"
                    && !tag.ends_with("Icon")
                    && !tag.starts_with("Icon")
                    && has_direct_visible_text(el)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn parse_tailwind_size_px(utility: &str) -> Option<f64> {
    let val = utility
        .strip_prefix("size-")
        .or_else(|| utility.strip_prefix("w-"))
        .or_else(|| utility.strip_prefix("h-"))?;
    if val == "px" {
        return Some(1.0);
    }
    if let Some(inner) = val.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return parse_px_or_rem(inner);
    }
    val.parse::<f64>().ok().map(|n| n * 4.0)
}

fn collect_all_static_text(jsx_el: &JSXElement<'_>) -> String {
    let mut out = String::new();
    for child in &jsx_el.children {
        match child {
            JSXChild::Text(t) => {
                out.push_str(t.value.as_str());
                out.push(' ');
            }
            JSXChild::Element(el) => {
                out.push_str(&collect_all_static_text(el));
                out.push(' ');
            }
            JSXChild::Fragment(frag) => {
                for fc in &frag.children {
                    if let JSXChild::Element(el) = fc {
                        out.push_str(&collect_all_static_text(el));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn starts_with_emoji(s: &str) -> bool {
    let Some(first_ch) = s.chars().next() else {
        return false;
    };
    let code = u32::from(first_ch);
    (0x1F300..=0x1FAFF).contains(&code) || (0x2600..=0x27BF).contains(&code)
}

fn is_tailwind_card_tokens(tokens: &[&str]) -> bool {
    let has_round = tokens
        .iter()
        .any(|t| *t == "rounded" || t.starts_with("rounded-"));
    let has_edge_or_bg = tokens.iter().any(|t| {
        *t == "border"
            || t.starts_with("border-")
            || t.starts_with("shadow")
            || t.starts_with("ring")
            || (t.starts_with("bg-") && *t != "bg-transparent")
    });
    has_round && has_edge_or_bg
}

fn collect_leaf_element_texts(jsx_el: &JSXElement<'_>, counts: &mut HashMap<String, usize>) {
    let has_el_children = jsx_el
        .children
        .iter()
        .any(|c| matches!(c, JSXChild::Element(_)));
    if !has_el_children {
        let txt = collect_all_static_text(jsx_el).trim().to_string();
        if !txt.is_empty() {
            *counts.entry(txt).or_insert(0) += 1;
        }
        return;
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            collect_leaf_element_texts(child_el, counts);
        }
    }
}

fn resolve_element_font_size_px(
    opening: &JSXOpeningElement<'_>,
    unvariant_tokens: &[&str],
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> Option<f64> {
    if let Some(num) = get_style_prop_number(opening, "fontSize") {
        return Some(num);
    }
    if let Some(s) = get_style_prop_str(opening, "fontSize", semantic, const_strings)
        && let Some(px) = parse_px_or_rem(&s)
    {
        return Some(px);
    }
    for &u in unvariant_tokens.iter().rev() {
        let px = match u {
            "text-xs" => Some(12.0),
            "text-sm" => Some(14.0),
            "text-base" => Some(16.0),
            "text-lg" => Some(18.0),
            "text-xl" => Some(20.0),
            "text-2xl" => Some(24.0),
            "text-3xl" => Some(30.0),
            "text-4xl" => Some(36.0),
            "text-5xl" => Some(48.0),
            "text-6xl" => Some(60.0),
            "text-7xl" => Some(72.0),
            "text-8xl" => Some(96.0),
            "text-9xl" => Some(128.0),
            _ => u
                .strip_prefix("text-[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(parse_px_or_rem),
        };
        if px.is_some() {
            return px;
        }
    }
    None
}

fn collect_subtree_font_sizes(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    out: &mut Vec<f64>,
) {
    let class_str =
        get_class_name_str(&jsx_el.opening_element, semantic, const_strings).unwrap_or_default();
    let unvariants: Vec<&str> = class_str
        .split_whitespace()
        .map(|t| t.rsplit(':').next().unwrap_or(t).trim_start_matches('!'))
        .collect();
    if let Some(px) = resolve_element_font_size_px(
        &jsx_el.opening_element,
        &unvariants,
        semantic,
        const_strings,
    ) {
        out.push(px);
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            collect_subtree_font_sizes(child_el, semantic, const_strings, out);
        }
    }
}

fn has_tabular_nums_in_ancestry(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for id in std::iter::once(node_id).chain(semantic.nodes().ancestor_ids(node_id)) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(id)
            && let Some(cls) = get_class_name_str(&el.opening_element, semantic, const_strings)
            && cls
                .split_whitespace()
                .any(|t| matches!(t, "tabular-nums" | "font-mono"))
        {
            return true;
        }
    }
    false
}

fn has_ancestor_with_class<F>(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
    pred: F,
) -> bool
where
    F: Fn(&str) -> bool,
{
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id)
            && let Some(cls) = get_class_name_str(&el.opening_element, semantic, const_strings)
            && cls.split_whitespace().any(&pred)
        {
            return true;
        }
    }
    false
}

fn has_card_ancestor(
    semantic: &Semantic<'_>,
    node_id: NodeId,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id)
            && let Some(cls) = get_class_name_str(&el.opening_element, semantic, const_strings)
        {
            let toks: Vec<&str> = cls.split_whitespace().collect();
            if is_tailwind_card_tokens(&toks) {
                return true;
            }
        }
    }
    false
}

fn has_enclosing_nav_or_aside(semantic: &Semantic<'_>, node_id: NodeId) -> bool {
    for anc_id in semantic.nodes().ancestor_ids(node_id) {
        if let AstKind::JSXElement(el) = semantic.nodes().kind(anc_id) {
            let tag = get_jsx_tag_name(&el.opening_element.name);
            if matches!(tag.as_str(), "nav" | "aside") {
                return true;
            }
        }
    }
    false
}

fn count_svg_primitives(jsx_el: &JSXElement<'_>, count: &mut usize) {
    for child in &jsx_el.children {
        if let JSXChild::Element(el) = child {
            let tag = get_jsx_tag_name(&el.opening_element.name);
            if matches!(tag.as_str(), "rect" | "circle" | "ellipse" | "polygon") {
                *count += 1;
            }
            count_svg_primitives(el, count);
        }
    }
}

fn count_placeholder_anchors(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    count: &mut usize,
) {
    for child in &jsx_el.children {
        if let JSXChild::Element(el) = child {
            let tag = get_jsx_tag_name(&el.opening_element.name);
            if tag == "a"
                && find_attr(&el.opening_element.attributes, "href")
                    .and_then(|a| get_attr_static_str(semantic, a, const_strings))
                    .as_deref()
                    == Some("#")
            {
                *count += 1;
            }
            count_placeholder_anchors(el, semantic, const_strings, count);
        }
    }
}

fn has_traffic_light_dots(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    let mut has_red = false;
    let mut has_yellow = false;
    let mut has_green = false;
    check_traffic_lights_recursive(
        jsx_el,
        semantic,
        const_strings,
        &mut has_red,
        &mut has_yellow,
        &mut has_green,
    );
    has_red && has_yellow && has_green
}

fn check_traffic_lights_recursive(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    has_red: &mut bool,
    has_yellow: &mut bool,
    has_green: &mut bool,
) {
    if let Some(cls) = get_class_name_str(&jsx_el.opening_element, semantic, const_strings)
        && cls.contains("rounded-full")
    {
        if cls.contains("bg-red-") {
            *has_red = true;
        }
        if cls.contains("bg-yellow-") {
            *has_yellow = true;
        }
        if cls.contains("bg-green-") {
            *has_green = true;
        }
    }
    for child in &jsx_el.children {
        if let JSXChild::Element(el) = child {
            check_traffic_lights_recursive(
                el,
                semantic,
                const_strings,
                has_red,
                has_yellow,
                has_green,
            );
        }
    }
}

#[derive(Default)]
struct PageSubtreeStats {
    card_count: usize,
    centered_paragraph_count: usize,
    font_families: HashSet<String>,
    pill_count: usize,
    emoji_tile_count: usize,
    glass_surface_count: usize,
    hover_scale_sites: Vec<(SourceLoc, ByteSpan)>,
    section_shell_count: usize,
    section_py_counts: HashMap<String, usize>,
}

fn collect_page_subtree_stats(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
    line_starts: &[u32],
    stats: &mut PageSubtreeStats,
) {
    let opening = &jsx_el.opening_element;
    let tag = get_jsx_tag_name(&opening.name);
    let cls = get_class_name_str(opening, semantic, const_strings).unwrap_or_default();
    let toks: Vec<&str> = cls.split_whitespace().collect();
    let txt = collect_all_static_text(jsx_el);
    let trimmed = txt.trim();

    if is_tailwind_card_tokens(&toks) && toks.iter().any(|t| t.starts_with("p-")) {
        stats.card_count += 1;
    }
    if tag == "p" && trimmed.len() >= 48 && toks.contains(&"text-center") {
        stats.centered_paragraph_count += 1;
    }
    if let Some(ff) = get_style_prop_str(opening, "fontFamily", semantic, const_strings) {
        let first = ff
            .split(',')
            .next()
            .unwrap_or(&ff)
            .trim()
            .to_ascii_lowercase();
        if !first.is_empty() {
            stats.font_families.insert(first);
        }
    }
    if !trimmed.is_empty()
        && trimmed.len() <= 32
        && toks.contains(&"rounded-full")
        && toks.iter().any(|t| t.starts_with("px-"))
    {
        stats.pill_count += 1;
    }
    if starts_with_emoji(trimmed)
        && trimmed.chars().count() <= 2
        && toks.iter().any(|t| t.starts_with("rounded"))
        && toks.iter().any(|t| t.starts_with("bg-"))
    {
        stats.emoji_tile_count += 1;
    }
    if toks.iter().any(|t| t.starts_with("backdrop-blur"))
        && toks.iter().any(|t| t.starts_with("bg-") && t.contains('/'))
    {
        stats.glass_surface_count += 1;
    }
    if toks.iter().any(|t| t.starts_with("hover:scale-")) {
        stats.hover_scale_sites.push((
            loc_from_line_starts(line_starts, opening.span.start),
            ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
        ));
    }
    if tag == "section"
        && toks.iter().any(|t| t.starts_with("py-2"))
        && jsx_el.children.iter().any(|c| {
            if let JSXChild::Element(child_el) = c {
                let c_cls = get_class_name_str(&child_el.opening_element, semantic, const_strings)
                    .unwrap_or_default();
                c_cls.contains("mx-auto") && c_cls.contains("max-w-")
            } else {
                false
            }
        })
    {
        stats.section_shell_count += 1;
    }
    if tag == "section" {
        for &t in &toks {
            let u = t.rsplit(':').next().unwrap_or(t).trim_start_matches('!');
            if u.starts_with("py-") {
                *stats.section_py_counts.entry(u.to_string()).or_insert(0) += 1;
            }
        }
    }

    for child in &jsx_el.children {
        if let JSXChild::Element(child_el) = child {
            collect_page_subtree_stats(child_el, semantic, const_strings, line_starts, stats);
        }
    }
}

fn has_descendant_text_center(
    jsx_el: &JSXElement<'_>,
    semantic: &Semantic<'_>,
    const_strings: &HashMap<SymbolId, String>,
) -> bool {
    for child in &jsx_el.children {
        if let JSXChild::Element(el) = child {
            if get_class_name_str(&el.opening_element, semantic, const_strings)
                .is_some_and(|cls| cls.split_whitespace().any(|t| t.ends_with("text-center")))
            {
                return true;
            }
            if has_descendant_text_center(el, semantic, const_strings) {
                return true;
            }
        }
    }
    false
}

fn is_numbered_section_marker_text(s: &str) -> bool {
    let trimmed = s
        .trim()
        .trim_start_matches(['0', '#'])
        .trim_end_matches(['.', '/', '—', '-']);
    !s.is_empty()
        && s.len() <= 4
        && (s.starts_with('0') || s.starts_with('#') || s.ends_with('.'))
        && !trimmed.is_empty()
        && trimmed.bytes().all(|b| b.is_ascii_digit())
}

fn is_icon_tile_element(el: &JSXElement<'_>, unvariant_tokens: &[&str]) -> bool {
    let has_box = unvariant_tokens
        .iter()
        .any(|u| u.starts_with("rounded") || u.starts_with("bg-") || u.starts_with("border"));
    let has_compact_size = unvariant_tokens
        .iter()
        .any(|u| parse_tailwind_size_px(u).is_some_and(|px| px <= 64.0));
    let has_icon = subtree_has_tag_matching(el, |t| {
        t == "svg" || t.ends_with("Icon") || t.starts_with("Icon")
    });
    has_box && (has_compact_size || has_icon)
}
