//! React Native (`rn-*`) and Expo (`expo-*`) AST and project-configuration rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

pub(crate) mod animations_and_styles;
pub(crate) mod lists_and_layout;
pub(crate) mod navigation_and_expo;
pub(crate) mod platform_and_config;

pub(crate) use self::platform_and_config::evaluate_react_native_and_expo_project_checks;

use std::path::Path;

use oxc_ast::{
    AstKind,
    ast::{Expression, ImportDeclarationSpecifier, Program, Statement, VariableDeclarationKind},
};
use oxc_semantic::Semantic;
use oxc_span::Span;

use crate::{
    config::DotoreConfig,
    graph::ProjectGraph,
    ir::{
        FileIr, JsxElementIr,
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::SemanticRuleSite,
    },
    matchers::find_jsx_attr as matcher_find_jsx_attr,
};

use self::{
    animations_and_styles::check_rn_call_rules,
    lists_and_layout::check_rn_jsx_element_rules,
    navigation_and_expo::{
        check_expo_env_destructuring, check_rn_import_rules, check_rn_platform_namespace_shaking,
    },
};

const REACT_NATIVE_TEXT_COMPONENTS: &[&str] = &[
    "Text",
    "TextInput",
    "Typography",
    "Paragraph",
    "Span",
    "H1",
    "H2",
    "H3",
    "H4",
    "H5",
    "H6",
    "TSpan",
    "Animated.Text",
];

const REACT_NATIVE_TEXT_KEYWORDS: &[&str] = &[
    "Text",
    "Title",
    "Label",
    "Heading",
    "Caption",
    "Subtitle",
    "Typography",
    "Paragraph",
    "Description",
    "Body",
];

const REACT_NATIVE_HOST_COMPONENTS: &[&str] = &[
    "View",
    "ScrollView",
    "SafeAreaView",
    "KeyboardAvoidingView",
    "ImageBackground",
    "Modal",
    "Pressable",
    "TouchableOpacity",
    "TouchableHighlight",
    "TouchableWithoutFeedback",
    "TouchableNativeFeedback",
];

pub(crate) const REACT_NATIVE_LIST_COMPONENTS: &[&str] = &[
    "FlatList",
    "SectionList",
    "VirtualizedList",
    "FlashList",
    "AnimatedFlashList",
    "LegendList",
    "AnimatedLegendList",
    "KeyboardAwareLegendList",
    "KeyboardAvoidingLegendList",
];

pub(crate) const SCROLL_CONTAINER_NAMES: &[&str] = &[
    "ScrollView",
    "FlatList",
    "SectionList",
    "VirtualizedList",
    "KeyboardAwareScrollView",
    "FlashList",
    "LegendList",
];

pub(crate) const RENDER_ITEM_PROP_NAMES: &[&str] =
    &["renderItem", "renderSectionHeader", "renderSectionFooter"];

pub(crate) const LIST_ROW_PRESS_PROPS: &[&str] = &[
    "onPress",
    "onLongPress",
    "onPressIn",
    "onPressOut",
    "onSelect",
    "onClick",
];

pub(crate) const DEPRECATED_RN_CORE_MODULES: &[&str] = &[
    "AsyncStorage",
    "Picker",
    "PickerIOS",
    "DatePickerIOS",
    "DatePickerAndroid",
    "ProgressBarAndroid",
    "ProgressViewIOS",
    "Slider",
    "ViewPagerAndroid",
    "WebView",
    "NetInfo",
    "CameraRoll",
    "Clipboard",
    "ImageEditor",
    "MaskedViewIOS",
];

pub(crate) const LEGACY_EXPO_PACKAGES: &[&str] = &[
    "expo-av",
    "expo-permissions",
    "expo-app-loading",
    "react-native-fast-image",
];

pub(crate) const JS_BOTTOM_SHEET_PACKAGES: &[&str] = &[
    "react-native-bottom-sheet",
    "react-native-modal-bottom-sheet",
    "react-native-raw-bottom-sheet",
    "react-native-modalize",
    "react-native-actions-sheet",
    "react-native-bottomsheet-reanimated",
    "@discord/bottom-sheet",
];

pub(crate) const PUBLIC_RN_ROOT_EXPORTS: &[&str] = &[
    "AccessibilityInfo",
    "ActivityIndicator",
    "Alert",
    "Animated",
    "Appearance",
    "AppRegistry",
    "AppState",
    "BackHandler",
    "Button",
    "DeviceEventEmitter",
    "DevSettings",
    "Dimensions",
    "DynamicColorIOS",
    "Easing",
    "FlatList",
    "I18nManager",
    "Image",
    "ImageBackground",
    "InputAccessoryView",
    "InteractionManager",
    "Keyboard",
    "KeyboardAvoidingView",
    "LayoutAnimation",
    "Linking",
    "LogBox",
    "Modal",
    "NativeEventEmitter",
    "NativeModules",
    "PanResponder",
    "PermissionsAndroid",
    "PixelRatio",
    "Platform",
    "PlatformColor",
    "Pressable",
    "RefreshControl",
    "SafeAreaView",
    "ScrollView",
    "SectionList",
    "Share",
    "StatusBar",
    "StyleSheet",
    "Switch",
    "Systrace",
    "Text",
    "TextInput",
    "ToastAndroid",
    "Touchable",
    "TouchableHighlight",
    "TouchableNativeFeedback",
    "TouchableOpacity",
    "TouchableWithoutFeedback",
    "TurboModuleRegistry",
    "UIManager",
    "Vibration",
    "View",
    "VirtualizedList",
    "VirtualizedSectionList",
];

pub(crate) const LEGACY_SHADOW_PROPS: &[&str] = &[
    "shadowColor",
    "shadowOffset",
    "shadowOpacity",
    "shadowRadius",
    "elevation",
];

pub(crate) const TOUCHABLE_COMPONENTS: &[&str] = &[
    "TouchableOpacity",
    "TouchableHighlight",
    "TouchableWithoutFeedback",
    "TouchableNativeFeedback",
];

pub(crate) const DETOX_ELEMENT_ACTIONS: &[&str] = &[
    "tap",
    "multiTap",
    "longPress",
    "longPressAndDrag",
    "typeText",
    "replaceText",
    "clearText",
    "tapReturnKey",
    "tapBackspaceKey",
    "scroll",
    "scrollTo",
    "scrollToIndex",
    "swipe",
    "pinch",
    "pinchWithAngle",
    "setColumnToValue",
    "setDatePickerDate",
    "adjustSliderToPosition",
    "performAccessibilityAction",
    "takeScreenshot",
    "getAttributes",
];

/// Returns `true` if `jsx` is a React Native raw-text violation under `graph`, `file`, and `config`.
#[must_use]
pub(crate) fn is_rn_raw_text_violation(
    graph: &ProjectGraph,
    file: &FileIr,
    jsx: &JsxElementIr,
    config: &DotoreConfig,
) -> bool {
    if !jsx.has_raw_text_child {
        return false;
    }

    let is_text_comp = |name: &str| {
        REACT_NATIVE_TEXT_COMPONENTS.contains(&name)
            || REACT_NATIVE_TEXT_KEYWORDS
                .iter()
                .any(|kw| name.contains(kw))
            || config.text_components.iter().any(|c| c == name)
    };

    if is_text_comp(&jsx.name) || jsx.ancestor_elements.iter().any(|a| is_text_comp(a)) {
        return false;
    }

    // `rawTextWrapperComponents` suppresses `rn-no-raw-text` when the wrapper's children are purely stringifiable,
    // and flags when mixed with element children.
    if config
        .raw_text_wrapper_components
        .iter()
        .any(|w| w == &jsx.name)
    {
        return jsx.has_element_children;
    }

    // Built-in React Native host components (`View`, `ScrollView`, `Pressable`, etc.) or `<fbt>`/`<fbs>` outside `<Text>`
    if REACT_NATIVE_HOST_COMPONENTS.contains(&jsx.name.as_str())
        || matches!(jsx.name.as_str(), "fbt" | "fbs")
    {
        return true;
    }

    // Resolve same-file or cross-file wrapper forwarding
    if jsx.is_component
        && let Some(target) =
            graph.resolve_children_forwarding_target(file, &jsx.name, jsx.is_imported_component)
    {
        if is_text_comp(&target) {
            return false;
        }
        if REACT_NATIVE_HOST_COMPONENTS.contains(&target.as_str()) {
            return true;
        }
    }

    false
}

/// Extracts all React Native and Expo AST rule sites in a single pass.
pub(crate) fn extract_react_native_sites(
    path: &Path,
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let source = semantic.source_text();
    let path_str = path.to_string_lossy().replace('\\', "/");
    let is_detox_file =
        path_str.contains(".e2e.") || path_str.starts_with("e2e/") || path_str.contains("/e2e/");
    let is_node_or_build_file = path_str.contains(".config.")
        || path_str.contains("/scripts/")
        || path_str.contains("/tools/")
        || path_str.contains("+api.")
        || path_str.contains(".server.")
        || path_str.contains(".test.")
        || path_str.contains(".spec.")
        || is_detox_file;

    // 1. Module import rules
    check_rn_import_rules(program, semantic, line_starts, sites);

    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let subject_name = find_enclosing_react_node(semantic, node_id)
            .and_then(|subj_id| get_subject_name(semantic, subj_id));

        match node.kind() {
            AstKind::VariableDeclarator(decl) => {
                check_expo_env_destructuring(
                    decl,
                    is_node_or_build_file,
                    &subject_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::StaticMemberExpression(mem) => {
                check_rn_platform_namespace_shaking(
                    program,
                    semantic,
                    mem,
                    &subject_name,
                    line_starts,
                    sites,
                );
            }
            AstKind::CallExpression(call) => {
                check_rn_call_rules(
                    program,
                    semantic,
                    node_id,
                    call,
                    &subject_name,
                    is_detox_file,
                    source,
                    line_starts,
                    sites,
                );
            }
            AstKind::JSXElement(jsx_el) => {
                check_rn_jsx_element_rules(
                    program,
                    semantic,
                    node_id,
                    jsx_el,
                    &subject_name,
                    source,
                    line_starts,
                    sites,
                );
            }
            _ => {}
        }
    }
}

pub(crate) fn is_process_env_expr(expr: &Expression<'_>) -> bool {
    if let Expression::StaticMemberExpression(mem) = expr.without_parentheses()
        && mem.property.name == "env"
        && let Expression::Identifier(obj) = mem.object.without_parentheses()
    {
        obj.name == "process"
    } else {
        false
    }
}

pub(crate) fn is_namespace_import_from(
    program: &Program<'_>,
    local_name: &str,
    module_src: &str,
) -> bool {
    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        if imp.source.value.as_str() != Some(module_src) {
            continue;
        }
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            if let ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) = spec
                && ns.local.name.as_str() == local_name
            {
                return true;
            }
        }
    }
    false
}

pub(crate) fn is_named_import_from(
    program: &Program<'_>,
    local_name: &str,
    exported_name: &str,
    module_src: &str,
) -> bool {
    for stmt in &program.body {
        let Statement::ImportDeclaration(imp) = stmt else {
            continue;
        };
        if imp.source.value.as_str() != Some(module_src) {
            continue;
        }
        let Some(specs) = &imp.specifiers else {
            continue;
        };
        for spec in specs {
            match spec {
                ImportDeclarationSpecifier::ImportSpecifier(s) => {
                    if s.local.name.as_str() == local_name
                        && s.imported.name().as_str() == exported_name
                    {
                        return true;
                    }
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                    if exported_name == "default" && s.local.name.as_str() == local_name {
                        return true;
                    }
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(_) => {}
            }
        }
    }
    false
}

pub(crate) fn find_jsx_attr<'a>(
    opening: &'a oxc_ast::ast::JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a oxc_ast::ast::JSXAttribute<'a>> {
    matcher_find_jsx_attr(&opening.attributes, name)
}

pub(crate) fn find_state_setter_in_attr(
    semantic: &Semantic<'_>,
    attr: &oxc_ast::ast::JSXAttribute<'_>,
) -> Option<Span> {
    let attr_span = attr.span;
    for (_, node) in semantic.nodes().iter_enumerated() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !attr_span.contains_inclusive(call.span) {
            continue;
        }
        if let Expression::Identifier(callee_id) = call.callee.without_parentheses()
            && callee_id.name.starts_with("set")
            && callee_id
                .name
                .chars()
                .nth(3)
                .is_some_and(|c| c.is_ascii_uppercase())
        {
            return Some(call.span);
        }
    }
    None
}

pub(crate) fn is_static_style_value(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        Expression::UnaryExpression(un) => is_static_style_value(semantic, &un.argument),
        Expression::BinaryExpression(bin) => {
            is_static_style_value(semantic, &bin.left)
                && is_static_style_value(semantic, &bin.right)
        }
        Expression::Identifier(ident) => {
            let Some(ref_id) = ident.reference_id.get() else {
                return false;
            };
            let Some(sym_id) = semantic.scoping().get_reference(ref_id).symbol_id() else {
                return false;
            };
            let decl_id = semantic.scoping().symbol_declaration(sym_id);
            if let AstKind::VariableDeclarator(decl) = semantic.nodes().kind(decl_id)
                && matches!(
                    semantic.nodes().parent_kind(decl_id),
                    AstKind::VariableDeclaration(vd) if vd.kind == VariableDeclarationKind::Const
                )
                && let Some(init) = &decl.init
            {
                return is_static_style_value(semantic, init);
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ir::parse_file_ir;
    use crate::rules::RuleId;

    #[test]
    fn react_native_submodules_expose_lists_animations_navigation_and_config_detectors() {
        let _ = (
            super::lists_and_layout::check_scrollview_and_list_jsx_rules
                as fn(_, _, _, _, _, _, _, _),
            super::animations_and_styles::check_rn_call_rules as fn(_, _, _, _, _, _, _, _, _),
            super::navigation_and_expo::check_rn_import_rules as fn(_, _, _, _),
            super::platform_and_config::evaluate_react_native_and_expo_project_checks
                as fn(_, _, _, _),
        );

        let ir = parse_file_ir(
            Path::new("src/Screen.tsx"),
            r##"
import { View, ScrollView, Dimensions, StyleSheet, Animated } from "react-native";
import { createStackNavigator } from "@react-navigation/stack";

const styles = StyleSheet.create({
    card: { shadowColor: "#000" },
});

export function Screen({ items }: { items: string[] }) {
    const w = Dimensions.get("window").width;
    const { API_URL } = process.env;
    return (
        <ScrollView style={[styles.card]}>
            {items.map((it) => <View key={it}>{String(w)}{String(API_URL)}{String(Boolean(Animated))}{String(Boolean(createStackNavigator))}</View>)}
        </ScrollView>
    );
}
"##,
        );
        let rules: Vec<RuleId> = ir.semantic_sites.iter().map(|s| s.rule).collect();
        assert!(rules.contains(&RuleId::RnPreferReanimated));
        assert!(rules.contains(&RuleId::RnNoNonNativeNavigator));
        assert!(rules.contains(&RuleId::RnNoLegacyShadowStyles));
        assert!(rules.contains(&RuleId::RnNoDimensionsGet));
        assert!(rules.contains(&RuleId::ExpoNoNonInlinedEnv));
        assert!(rules.contains(&RuleId::RnNoSingleElementStyleArray));
        assert!(rules.contains(&RuleId::RnNoScrollviewMappedList));
    }
}
