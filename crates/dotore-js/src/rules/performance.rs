//! React re-render performance, hydration, motion, and rendering rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; React performance rule detectors match only relevant AST node kinds"
)]

mod animation_and_jsx;
mod hydration_and_routing;
mod rerender_and_hooks;

use std::path::Path;

use oxc_ast::{
    AstKind,
    ast::{CallExpression, Expression, JSXElementName},
};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;

use self::{
    animation_and_jsx::{
        check_jsx_opening_performance_rules, check_motion_value_constructor_in_render,
        check_no_global_css_variable_animation, check_no_unthrottled_scroll_mutation,
        check_unbounded_animation_frame_loop, check_web_animation_keyframes,
    },
    hydration_and_routing::{
        check_no_hydration_branch_on_browser_global, check_no_locale_format_in_render,
        check_no_unguarded_browser_global_in_render,
        check_react_router_loader_fetch_forwards_signal, check_react_router_loader_parallel_fetch,
        check_react_router_prefer_route_lazy, check_rendering_hydration_mismatch_time,
        check_rendering_hydration_no_flicker,
    },
    rerender_and_hooks::{
        build_same_file_memo_registry, check_component_function,
        check_no_eager_new_in_use_state_initializer, check_no_match_media_in_state_initializer,
        check_no_usememo_simple_expression, check_rerender_transitions_scroll,
        extract_component_fn_parts,
    },
};
use crate::{
    ir::{
        react_ast::is_component_name,
        types::{ModuleIr, SemanticRuleSite},
    },
    matchers::unwrap_expr,
};

const LAYOUT_PROPERTIES: &[&str] = &[
    "width",
    "height",
    "top",
    "left",
    "right",
    "bottom",
    "padding",
    "paddingTop",
    "paddingRight",
    "paddingBottom",
    "paddingLeft",
    "margin",
    "marginTop",
    "marginRight",
    "marginBottom",
    "marginLeft",
    "borderWidth",
    "fontSize",
    "lineHeight",
    "gap",
];

const MOTION_ANIMATE_PROPS: &[&str] = &[
    "animate",
    "initial",
    "exit",
    "whileHover",
    "whileTap",
    "whileFocus",
    "whileDrag",
    "whileInView",
];

const INDIVIDUAL_MOTION_TRANSFORM_PROPS: &[&str] = &[
    "x",
    "y",
    "z",
    "translateX",
    "translateY",
    "translateZ",
    "scale",
    "scaleX",
    "scaleY",
    "rotate",
    "rotateX",
    "rotateY",
    "rotateZ",
    "skewX",
    "skewY",
    "transformPerspective",
];

const HIGH_FREQUENCY_DOM_EVENTS: &[&str] = &[
    "scroll",
    "mousemove",
    "wheel",
    "pointermove",
    "touchmove",
    "drag",
];

const DEP_HOOK_NAMES: &[&str] = &[
    "useEffect",
    "useLayoutEffect",
    "useMemo",
    "useCallback",
    "useInsertionEffect",
    "useImperativeHandle",
];

const CHEAP_CONSTRUCTORS: &[&str] = &[
    "Boolean",
    "Number",
    "Object",
    "String",
    "Array",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "Date",
    "RegExp",
    "URL",
    "URLSearchParams",
    "Headers",
    "DOMRect",
    "DOMRectReadOnly",
    "DOMPoint",
    "DOMPointReadOnly",
    "DOMMatrix",
    "DOMMatrixReadOnly",
    "DOMQuad",
    "Path2D",
];

const BROWSER_GLOBALS: &[&str] = &[
    "window",
    "document",
    "localStorage",
    "sessionStorage",
    "navigator",
    "location",
    "history",
    "screen",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoStatus {
    Memoized,
    CustomComparatorMemo,
    NotMemoized,
}

/// Extracts React re-render, hydration, motion, and rendering performance rule sites.
pub(crate) fn extract_performance_sites(
    _path: &Path,
    semantic: &Semantic<'_>,
    _module: &ModuleIr,
    line_starts: &[u32],
    out: &mut Vec<SemanticRuleSite>,
) {
    let memo_registry = build_same_file_memo_registry(semantic);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        match node.kind() {
            AstKind::Function(func) => {
                if let Some(id) = &func.id
                    && is_component_name(id.name.as_str())
                    && let Some(body) = &func.body
                {
                    check_component_function(
                        node_id,
                        &func.params.items,
                        &body.statements,
                        body.span,
                        &memo_registry,
                        semantic,
                        line_starts,
                        out,
                    );
                }
                check_unbounded_animation_frame_loop(
                    node_id,
                    func.id.as_ref().map(|i| i.name.as_str()),
                    func.body.as_ref().map(|b| b.span),
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::VariableDeclarator(decl) => {
                if let Some(id) = decl.id.get_binding_identifier()
                    && let Some(init) = &decl.init
                {
                    let name = id.name.as_str();
                    if is_component_name(name)
                        && let Some((params, stmts, body_span)) = extract_component_fn_parts(init)
                    {
                        check_component_function(
                            node_id,
                            params,
                            stmts,
                            body_span,
                            &memo_registry,
                            semantic,
                            line_starts,
                            out,
                        );
                    }
                    let fn_body_span = match unwrap_expr(init) {
                        Expression::ArrowFunctionExpression(a) => Some(a.body.span()),
                        Expression::FunctionExpression(f) => f.body.as_ref().map(|b| b.span),
                        _ => None,
                    };
                    check_unbounded_animation_frame_loop(
                        node_id,
                        Some(name),
                        fn_body_span,
                        semantic,
                        line_starts,
                        out,
                    );
                }
            }
            AstKind::CallExpression(call) => {
                check_rerender_transitions_scroll(node_id, call, semantic, line_starts, out);
                check_no_match_media_in_state_initializer(
                    node_id,
                    call,
                    semantic,
                    line_starts,
                    out,
                );
                check_no_eager_new_in_use_state_initializer(
                    node_id,
                    call,
                    semantic,
                    line_starts,
                    out,
                );
                check_no_usememo_simple_expression(node_id, call, semantic, line_starts, out);
                check_no_unthrottled_scroll_mutation(node_id, call, semantic, line_starts, out);
                check_no_global_css_variable_animation(node_id, call, semantic, line_starts, out);
                check_web_animation_keyframes(node_id, call, semantic, line_starts, out);
                check_motion_value_constructor_in_render(node_id, call, semantic, line_starts, out);
                check_rendering_hydration_no_flicker(node_id, call, semantic, line_starts, out);
                check_no_locale_format_in_render(node_id, call, semantic, line_starts, out);
                check_react_router_loader_fetch_forwards_signal(
                    node_id,
                    call,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::JSXOpeningElement(opening) => {
                check_jsx_opening_performance_rules(
                    node_id,
                    opening,
                    &memo_registry,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::JSXExpressionContainer(container) => {
                check_rendering_hydration_mismatch_time(
                    node_id,
                    container,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::ObjectExpression(obj) => {
                check_react_router_prefer_route_lazy(node_id, obj, semantic, line_starts, out);
            }
            AstKind::FunctionBody(body) => {
                check_react_router_loader_parallel_fetch(
                    node_id,
                    &body.statements,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::IdentifierReference(ident) => {
                check_no_unguarded_browser_global_in_render(
                    node_id,
                    ident,
                    semantic,
                    line_starts,
                    out,
                );
            }
            AstKind::ConditionalExpression(cond) => {
                check_no_hydration_branch_on_browser_global(
                    node_id,
                    &cond.test,
                    semantic,
                    line_starts,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn is_react_named_hook_call(call: &CallExpression<'_>, hook_name: &str) -> bool {
    match unwrap_expr(&call.callee) {
        Expression::Identifier(id) => id.name == hook_name,
        Expression::StaticMemberExpression(mem) => {
            mem.property.name == hook_name
                && matches!(
                    unwrap_expr(&mem.object),
                    Expression::Identifier(id) if id.name == "React" || id.name == "react"
                )
        }
        _ => false,
    }
}

fn extract_jsx_identifier_name<'a>(name: &'a JSXElementName<'a>) -> Option<&'a str> {
    match name {
        JSXElementName::Identifier(id) => Some(id.name.as_str()),
        JSXElementName::IdentifierReference(id) => Some(id.name.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;

    use super::*;
    use crate::{
        ir::{compute_line_starts, types::ModuleIr},
        rules::RuleId,
    };

    fn run_performance_sites(src: &str) -> Vec<SemanticRuleSite> {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, src, SourceType::tsx()).parse();
        let semantic = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program)
            .semantic;
        let line_starts = compute_line_starts(src);
        let module = ModuleIr::default();
        let mut sites = Vec::new();
        extract_performance_sites(
            Path::new("Component.tsx"),
            &semantic,
            &module,
            &line_starts,
            &mut sites,
        );
        sites
    }

    #[test]
    fn detects_rerender_and_hooks_rules() {
        let src = r#"
import { useState, useMemo } from "react";

export function Dashboard({ items = [] }: { items?: string[] }) {
    const [worker] = useState(new Worker("worker.js"));
    const doubled = useMemo(() => 1 + 2, []);
    const header = <header>Static Title</header>;
    return <div>{items.length}{doubled}{header}{String(worker)}</div>;
}
"#;
        let sites = run_performance_sites(src);
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoEagerNewInUseStateInitializer)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoUsememoSimpleExpression)
        );
        assert!(sites.iter().any(|s| s.rule == RuleId::RenderingHoistJsx));
    }

    #[test]
    fn detects_animation_and_jsx_rules() {
        let src = r#"
export function AnimatedCard() {
    return (
        <div className="transition-all will-change-transform">
            <motion.div animate={{ width: 200, scale: 0 }} />
            <img srcSet="hero-400.jpg 400w, hero-800.jpg 800w" loading="lazy" fetchPriority="high" />
        </div>
    );
}
"#;
        let sites = run_performance_sites(src);
        assert!(sites.iter().any(|s| s.rule == RuleId::NoTransitionAll));
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoPermanentWillChange)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoLayoutPropertyAnimation)
        );
        assert!(sites.iter().any(|s| s.rule == RuleId::NoScaleFromZero));
        assert!(sites.iter().any(|s| s.rule == RuleId::NoSrcsetWithoutSizes));
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoImgLazyWithHighFetchpriority)
        );
    }

    #[test]
    fn detects_hydration_and_routing_rules() {
        let src = r#"
export async function loader({ request }: { request: Request }) {
    const users = await fetch("/api/users");
    const posts = await fetch("/api/posts");
    return { users, posts };
}

export function Clock({ date }: { date: Date }) {
    const path = window.location.pathname;
    return <div>{Date.now()} {date.toLocaleDateString()} {path}</div>;
}
"#;
        let sites = run_performance_sites(src);
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::ReactRouterLoaderParallelFetch)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::ReactRouterLoaderFetchForwardsSignal)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::RenderingHydrationMismatchTime)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoLocaleFormatInRender)
        );
        assert!(
            sites
                .iter()
                .any(|s| s.rule == RuleId::NoUnguardedBrowserGlobalInRenderOrHookInit)
        );
    }
}
