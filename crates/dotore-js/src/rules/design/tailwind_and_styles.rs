//! Tailwind utility class, inline `style={{...}}`, and CSS-in-JS tagged-template design rules.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast AST enums have 200+ variants and JSX/CSS AST traversal matches only relevant node kinds"
)]

use std::collections::{HashMap, HashSet};

use oxc_ast::ast::{Expression, JSXAttribute, JSXAttributeValue, TaggedTemplateExpression};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;

use crate::{
    ir::{
        ByteSpan, SourceLoc,
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    matchers::{eval_numeric_expr, eval_static_str},
    rules::{AutofixPatch, ByteEdit, RuleId},
};

use super::{LAYOUT_TRANSITION_PROPS, parse_px_or_rem, push_design_site};

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates className and style attribute design rules in one pass"
)]
pub(super) fn check_jsx_attribute_design(
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

pub(super) fn check_class_name_literal_design(
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
pub(super) fn check_inline_style_design(
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

pub(super) fn check_tagged_template_design(
    semantic: &Semantic<'_>,
    tagged: &TaggedTemplateExpression<'_>,
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
