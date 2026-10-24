//! Single-pass detectors for Leptos/Dioxus reactive signal **Render Cascades** and
//! boolean parameter architecture rules:
//!
//! 1. `rs-ui-no-derived-signal-in-effect` ([`RuleId::RsUiNoDerivedSignalInEffect`])
//! 2. `rs-arch-no-many-boolean-params` ([`RuleId::RsArchNoManyBooleanParams`])

use dotore_core::{ByteSpan, RuleId, SourceLoc};
use syn::{
    Expr, ExprCall, ExprMacro, ExprMethodCall, File, FnArg, ImplItemFn, ItemFn, ItemImpl, ItemMod,
    Signature, TraitItemFn,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::matchers::{
    RsCandidateFinding, RsScopeTracker, extract_receiver_ident, is_bool_type, loc_at, span_to_bytes,
};

/// Extracts candidate findings for Leptos/Dioxus UI signal and boolean parameter architecture rules from `ast`.
pub(crate) fn extract_ui_and_arch_findings(
    ast: &File,
    line_starts: &[u32],
    out: &mut Vec<RsCandidateFinding>,
) {
    let mut visitor = UiSignalsAndArchVisitor {
        line_starts,
        findings: out,
        scope: RsScopeTracker::for_file(ast),
    };
    visitor.visit_file(ast);
}

struct UiSignalsAndArchVisitor<'a> {
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
}

impl UiSignalsAndArchVisitor<'_> {
    fn span_to_bytes(&self, span: proc_macro2::Span) -> ByteSpan {
        span_to_bytes(span)
    }

    fn loc_at(&self, byte_offset: u32) -> SourceLoc {
        loc_at(self.line_starts, byte_offset)
    }

    fn check_reactive_effect_call(&mut self, node: &ExprCall) {
        let Some(effect_fn) = extract_reactive_effect_fn_name(&node.func) else {
            return;
        };
        for arg in &node.args {
            let Expr::Closure(closure) = arg else {
                continue;
            };
            let mut inspector = EffectSignalInspector::default();
            inspector.visit_expr(&closure.body);
            if let Some((write_target, write_span)) = inspector.first_signal_write
                && inspector.has_signal_read
            {
                let span = self.span_to_bytes(write_span);
                let loc = self.loc_at(span.start);
                self.findings.push(RsCandidateFinding::new(
                    RuleId::RsUiNoDerivedSignalInEffect,
                    self.scope.subject_name(),
                    write_target.clone(),
                    "rsUiNoDerivedSignalInEffect",
                    format!(
                        "Reactive signal write `{write_target}` inside `{effect_fn}(...)` computes derived state from another signal; use `Memo::new(move |_| ...)` or `use_memo(move || ...)` to avoid a Render Cascade."
                    ),
                    loc,
                    span,
                ));
                break;
            }
        }
    }

    fn check_many_boolean_params(&mut self, sig: &Signature) {
        if self.scope.in_test() {
            return;
        }
        let mut bool_count = 0usize;

        for input in &sig.inputs {
            let FnArg::Typed(pat_type) = input else {
                continue;
            };
            if is_bool_type(&pat_type.ty) {
                bool_count += 1;
            }
        }

        if bool_count >= 3 {
            let span = self.span_to_bytes(sig.span());
            let ident_span = self.span_to_bytes(sig.ident.span());
            let loc = self.loc_at(ident_span.start);
            let fn_name = sig.ident.to_string();
            self.findings.push(RsCandidateFinding::new(
                RuleId::RsArchNoManyBooleanParams,
                self.scope.subject_name(),
                fn_name.clone(),
                "rsArchNoManyBooleanParams",
                format!(
                    "Function `{fn_name}` declares {bool_count} `bool` parameters; replace multiple boolean flags with an options struct or domain `enum`."
                ),
                loc,
                span,
            ));
        }
    }
}

impl<'ast> Visit<'ast> for UiSignalsAndArchVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let snap = self.scope.enter_mod(i);
        visit::visit_item_mod(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let snap = self.scope.enter_impl(i);
        visit::visit_item_impl(self, i);
        self.scope.exit(snap);
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        let snap = self.scope.enter_fn(i);
        self.check_many_boolean_params(&i.sig);
        visit::visit_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_impl_item_fn(&mut self, i: &'ast ImplItemFn) {
        let snap = self.scope.enter_method(i);
        self.check_many_boolean_params(&i.sig);
        visit::visit_impl_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast TraitItemFn) {
        let snap = self.scope.enter_trait_fn(i);
        self.check_many_boolean_params(&i.sig);
        visit::visit_trait_item_fn(self, i);
        self.scope.exit(snap);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if !self.scope.in_test() {
            self.check_reactive_effect_call(node);
        }
        visit::visit_expr_call(self, node);
    }
}

fn extract_reactive_effect_fn_name(func: &Expr) -> Option<String> {
    let Expr::Path(expr_path) = func else {
        return None;
    };
    let segs: Vec<String> = expr_path
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    let last = segs.last()?.as_str();
    if matches!(
        last,
        "create_effect"
            | "create_isomorphic_effect"
            | "create_render_effect"
            | "use_effect"
            | "use_reactive"
    ) {
        return Some(last.to_string());
    }
    if last == "new"
        && segs.len() >= 2
        && matches!(
            segs[segs.len() - 2].as_str(),
            "Effect" | "RenderEffect" | " IsoEffect"
        )
    {
        return Some(format!("{}::new", segs[segs.len() - 2]));
    }
    None
}

#[derive(Default)]
struct EffectSignalInspector {
    has_signal_read: bool,
    first_signal_write: Option<(String, proc_macro2::Span)>,
}

impl<'ast> Visit<'ast> for EffectSignalInspector {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(
            method.as_str(),
            "get" | "get_untracked" | "read" | "with" | "with_untracked" | "peek"
        ) {
            self.has_signal_read = true;
        }
        if matches!(
            method.as_str(),
            "set" | "update" | "set_untracked" | "update_untracked" | "write"
        ) && self.first_signal_write.is_none()
        {
            let recv =
                extract_receiver_ident(&node.receiver).unwrap_or_else(|| "signal".to_string());
            self.first_signal_write = Some((format!("{recv}.{method}"), node.span()));
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(p) = node.func.as_ref()
            && p.qself.is_none()
            && let Some(ident) = p.path.get_ident()
        {
            let name = ident.to_string();
            if name.starts_with("set_") && !node.args.is_empty() {
                if self.first_signal_write.is_none() {
                    self.first_signal_write = Some((name, node.span()));
                }
            } else if node.args.is_empty() && name.chars().next().is_some_and(char::is_lowercase) {
                self.has_signal_read = true;
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast ExprMacro) {
        let tokens = node.mac.tokens.to_string().replace(' ', "");
        if tokens.contains(".get(")
            || tokens.contains(".get_untracked(")
            || tokens.contains(".read(")
            || tokens.contains(".with(")
        {
            self.has_signal_read = true;
        }
        visit::visit_expr_macro(self, node);
    }
}
