//! React Native and Expo module import, navigation, bottom-sheet, `expo-image`,
//! `process.env` inlining, and `Platform` tree-shaking rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use oxc_ast::{
    AstKind,
    ast::{
        BindingPattern, Expression, ImportDeclarationSpecifier, JSXAttributeName, JSXChild,
        JSXElement, JSXElementName, Program, Statement,
    },
};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;

use super::{
    DEPRECATED_RN_CORE_MODULES, JS_BOTTOM_SHEET_PACKAGES, LEGACY_EXPO_PACKAGES,
    PUBLIC_RN_ROOT_EXPORTS, TOUCHABLE_COMPONENTS, find_jsx_attr, find_state_setter_in_attr,
    is_named_import_from, is_namespace_import_from, is_process_env_expr,
};
use crate::{
    ir::types::SemanticRuleSite,
    matchers::push_semantic_site,
    rules::RuleId,
};

pub(crate) fn check_rn_import_rules(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();
    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        if imp.import_kind.is_type() {
            continue;
        }
        let Some(src) = imp.source.value.as_str() else {
            continue;
        };

        // 1. `rn-no-deep-imports`
        if let Some(after) = src.strip_prefix("react-native/Libraries/") {
            let last_seg = after.rsplit('/').next().unwrap_or(after);
            let seg_stem = last_seg.split('.').next().unwrap_or(last_seg);
            if src == "react-native/Libraries/NewAppScreen"
                || PUBLIC_RN_ROOT_EXPORTS.contains(&seg_stem)
            {
                push_semantic_site(
                    sites,
                    RuleId::RnNoDeepImports,
                    None,
                    "rnNoDeepImports",
                    src,
                    format!(
                        "Deep import from \"{src}\" reaches into internal React Native paths; import \"{seg_stem}\" from \"react-native\" instead."
                    ),
                    line_starts,
                    imp.span,
                );
            }
        }

        // 2. `rn-no-legacy-expo-packages`
        for &legacy_pkg in LEGACY_EXPO_PACKAGES {
            if src == legacy_pkg || src.starts_with(&format!("{legacy_pkg}/")) {
                push_semantic_site(
                    sites,
                    RuleId::RnNoLegacyExpoPackages,
                    None,
                    "rnNoLegacyExpoPackages",
                    legacy_pkg,
                    format!(
                        "Your users are exposed to unfixed bugs when \"{legacy_pkg}\" is no longer maintained."
                    ),
                    line_starts,
                    imp.span,
                );
                break;
            }
        }

        // 3. `rn-bottom-sheet-prefer-native`
        if JS_BOTTOM_SHEET_PACKAGES.contains(&src) {
            push_semantic_site(
                sites,
                RuleId::RnBottomSheetPreferNative,
                None,
                "rnBottomSheetPreferNative",
                src,
                format!(
                    "Users get JS-driven sheet gestures and presentation with {src}, instead of the platform-native formSheet behavior."
                ),
                line_starts,
                imp.span,
            );
        }

        // 4. `rn-no-non-native-navigator`
        if matches!(src, "@react-navigation/stack" | "@react-navigation/drawer")
            && let Some(specs) = &imp.specifiers
            && specs.iter().any(|s| match s {
                ImportDeclarationSpecifier::ImportDefaultSpecifier(_)
                | ImportDeclarationSpecifier::ImportNamespaceSpecifier(_) => true,
                ImportDeclarationSpecifier::ImportSpecifier(sp) => {
                    !sp.import_kind.is_type()
                        && sp.imported.name().as_str().starts_with("create")
                        && sp.imported.name().as_str().ends_with("Navigator")
                }
            })
        {
            push_semantic_site(
                sites,
                RuleId::RnNoNonNativeNavigator,
                None,
                "rnNoNonNativeNavigator",
                src,
                format!(
                    "Users get JS-driven transitions and gestures from {src}, instead of platform-native navigation behavior."
                ),
                line_starts,
                imp.span,
            );
        }

        // 5. `react-native` named specifier checks (`rn-no-deprecated-modules`, `rn-no-panresponder`, `rn-prefer-pressable`, `rn-prefer-expo-image`)
        if matches!(src, "react-native" | "react-native-gesture-handler")
            && let Some(specs) = &imp.specifiers
        {
            for spec in specs {
                let ImportDeclarationSpecifier::ImportSpecifier(sp) = spec else {
                    continue;
                };
                if sp.import_kind.is_type() {
                    continue;
                };
                let imported = sp.imported.name().as_str();
                let local = sp.local.name.as_str();

                if src == "react-native" && DEPRECATED_RN_CORE_MODULES.contains(&imported) {
                    push_semantic_site(
                        sites,
                        RuleId::RnNoDeprecatedModules,
                        None,
                        "rnNoDeprecatedModules",
                        imported,
                        format!(
                            "Your users hit a crash from \"{imported}\", which was removed from react-native."
                        ),
                        line_starts,
                        sp.span,
                    );
                }

                if src == "react-native" && imported == "PanResponder" {
                    push_semantic_site(
                        sites,
                        RuleId::RnNoPanresponder,
                        None,
                        "rnNoPanresponder",
                        "PanResponder",
                        "PanResponder runs gesture handling on the JS thread, which stutters under load. Use react-native-gesture-handler (`Gesture.Pan()`) so gestures run on the native UI thread.".to_string(),
                        line_starts,
                        sp.span,
                    );
                }

                if TOUCHABLE_COMPONENTS.contains(&imported) {
                    push_semantic_site(
                        sites,
                        RuleId::RnPreferPressable,
                        None,
                        "rnPreferPressable",
                        imported,
                        format!(
                            "Your users miss <Pressable>'s flexible press feedback when you use {imported}, which is old & frozen."
                        ),
                        line_starts,
                        sp.span,
                    );
                }

                if src == "react-native"
                    && imported == "Image"
                    && should_flag_rn_prefer_expo_image(semantic, local, source)
                {
                    push_semantic_site(
                        sites,
                        RuleId::RnPreferExpoImage,
                        None,
                        "rnPreferExpoImage",
                        "Image",
                        "React Native's <Image> lacks disk caching and placeholders; prefer <Image> from expo-image.".to_string(),
                        line_starts,
                        sp.span,
                    );
                }
                if src == "react-native" && imported == "Animated" {
                    push_semantic_site(
                        sites,
                        RuleId::RnPreferReanimated,
                        None,
                        "rnPreferReanimated",
                        "Animated",
                        "Prefer `react-native-reanimated` over React Native's legacy `Animated` API so animations run on the UI thread.".to_string(),
                        line_starts,
                        sp.span,
                    );
                }
            }
        }
    }
}

fn should_flag_rn_prefer_expo_image(
    semantic: &Semantic<'_>,
    local_image_name: &str,
    source: &str,
) -> bool {
    let mut has_any_jsx_usage = false;
    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXOpeningElement(opening) = node.kind() else {
            continue;
        };
        let is_match = match &opening.name {
            JSXElementName::Identifier(id) => id.name.as_str() == local_image_name,
            JSXElementName::IdentifierReference(id) => id.name.as_str() == local_image_name,
            _ => false,
        };
        if !is_match {
            continue;
        }
        has_any_jsx_usage = true;
        // If `source={require("./logo.png")}` is a bundled static asset, skip it
        let mut is_bundled_require = false;
        for attr_item in &opening.attributes {
            let Some(attr) = attr_item.as_attribute() else {
                continue;
            };
            if let JSXAttributeName::Identifier(attr_id) = &attr.name
                && attr_id.name == "source"
                && let Some(val) = &attr.value
            {
                let val_text = val.span().source_text(source);
                if val_text.contains("require(")
                    && (val_text.contains(".png")
                        || val_text.contains(".jpg")
                        || val_text.contains(".jpeg")
                        || val_text.contains(".gif")
                        || val_text.contains(".webp")
                        || val_text.contains(".bmp"))
                {
                    is_bundled_require = true;
                }
            }
        }
        if !is_bundled_require {
            return true;
        }
    }
    !has_any_jsx_usage
}

#[expect(
    clippy::too_many_arguments,
    reason = "Checks BottomSheet JSX element and children rules in a single pass"
)]
pub(crate) fn check_bottom_sheet_jsx_rules(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    el_name: &str,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;

    if el_name == "BottomSheetScrollView"
        && is_named_import_from(
            program,
            "BottomSheetScrollView",
            "BottomSheetScrollView",
            "@gorhom/bottom-sheet",
        )
    {
        for attr_item in &opening.attributes {
            let Some(attr) = attr_item.as_attribute() else {
                continue;
            };
            if let JSXAttributeName::Identifier(attr_id) = &attr.name {
                let prop_name = attr_id.name.as_str();
                if matches!(
                    prop_name,
                    "decelerationRate" | "onScrollBeginDrag" | "scrollEventThrottle"
                ) {
                    push_semantic_site(
                        sites,
                        RuleId::RnBottomSheetNoIgnoredScrollProp,
                        subject_name.clone(),
                        "rnBottomSheetNoIgnoredScrollProp",
                        prop_name,
                        format!(
                            "BottomSheetScrollView ignores `{prop_name}`, so this prop cannot affect scrolling. Remove it or handle the behavior outside the scrollable."
                        ),
                        line_starts,
                        attr.span,
                    );
                }
            }
        }
    }

    if matches!(el_name, "BottomSheet" | "BottomSheetModal") {
        // `rn-bottom-sheet-no-state-in-on-animate`
        if let Some(on_animate_attr) = find_jsx_attr(opening, "onAnimate")
            && let Some(setter_span) = find_state_setter_in_attr(semantic, on_animate_attr)
        {
            push_semantic_site(
                sites,
                RuleId::RnBottomSheetNoStateInOnAnimate,
                subject_name.clone(),
                "rnBottomSheetNoStateInOnAnimate",
                "onAnimate",
                "This onAnimate handler starts a React state update as the Bottom Sheet begins moving, adding render work to the transition. Use animatedIndex or animatedPosition for animation-coupled UI.".to_string(),
                line_starts,
                setter_span,
            );
        }

        // `rn-bottom-sheet-use-integrated-scrollable`
        for child in &jsx_el.children {
            let JSXChild::Element(child_el) = child else {
                continue;
            };
            let child_name = child_el
                .opening_element
                .name
                .span()
                .source_text(source)
                .trim();
            if matches!(
                child_name,
                "ScrollView" | "FlatList" | "SectionList" | "VirtualizedList"
            ) && is_named_import_from(program, child_name, child_name, "react-native")
            {
                push_semantic_site(
                    sites,
                    RuleId::RnBottomSheetUseIntegratedScrollable,
                    subject_name.clone(),
                    "rnBottomSheetUseIntegratedScrollable",
                    child_name,
                    format!(
                        "React Native's `{child_name}` does not coordinate gestures with this Bottom Sheet. Use `BottomSheet{child_name}` from @gorhom/bottom-sheet."
                    ),
                    line_starts,
                    child_el.opening_element.span,
                );
            }
        }
    }
}

pub(crate) fn check_expo_env_destructuring(
    decl: &oxc_ast::ast::VariableDeclarator<'_>,
    is_node_or_build_file: bool,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if !is_node_or_build_file
        && let BindingPattern::ObjectPattern(_) = &decl.id
        && let Some(init) = &decl.init
        && is_process_env_expr(init)
    {
        push_semantic_site(
            sites,
            RuleId::ExpoNoNonInlinedEnv,
            subject_name.clone(),
            "expoNoNonInlinedEnv",
            "process.env",
            "Destructuring `process.env` isn't inlined by babel-preset-expo, so the values are `undefined` at runtime. Read each var via `process.env.EXPO_PUBLIC_NAME`.".to_string(),
            line_starts,
            decl.span,
        );
    }
}

pub(crate) fn check_rn_platform_namespace_shaking(
    program: &Program<'_>,
    mem: &oxc_ast::ast::StaticMemberExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    if mem.property.name == "Platform"
        && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
        && is_namespace_import_from(program, obj_id.name.as_str(), "react-native")
    {
        push_semantic_site(
            sites,
            RuleId::RnPlatformShakingUseDirectImport,
            subject_name.clone(),
            "rnPlatformShakingUseDirectImport",
            "Platform",
            "Expo cannot tree-shake platform branches reached through the React Native namespace, so both platform paths stay in the bundle.".to_string(),
            line_starts,
            mem.span,
        );
    }
}
