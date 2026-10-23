//! React Native (`rn-*`) and Expo (`expo-*`) AST and project-configuration rule detectors.
#![expect(
    clippy::wildcard_enum_match_arm,
    clippy::excessive_nesting,
    reason = "oxc_ast node/expression enums have dozens of variants; rule detectors match only targeted AST shapes"
)]

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use oxc_ast::{
    AstKind,
    ast::{
        Argument, ArrowFunctionBody, AssignmentTarget, BindingPattern, CallExpression, Expression,
        ImportDeclarationSpecifier, JSXAttributeName, JSXAttributeValue, JSXChild, JSXElement,
        JSXElementName, JSXExpression, LogicalOperator, ObjectExpression, ObjectPropertyKind,
        Program, Statement, VariableDeclarationKind,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::{GetSpan, Span};
use serde_json::Value;

use crate::{
    config::{Capability, DotoreConfig, WorkspacePackage, strip_jsonc},
    graph::ProjectGraph,
    ir::{
        ByteSpan, FileIr, JsxElementIr, SourceLoc,
        react_ast::{find_enclosing_react_node, get_subject_name},
        types::{SemanticRuleSite, loc_from_line_starts},
    },
    rules::{Diagnostic, RuleId, RuleSeverity},
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

const REACT_NATIVE_LIST_COMPONENTS: &[&str] = &[
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

const SCROLL_CONTAINER_NAMES: &[&str] = &[
    "ScrollView",
    "FlatList",
    "SectionList",
    "VirtualizedList",
    "KeyboardAwareScrollView",
    "FlashList",
    "LegendList",
];

const RENDER_ITEM_PROP_NAMES: &[&str] =
    &["renderItem", "renderSectionHeader", "renderSectionFooter"];

const LIST_ROW_PRESS_PROPS: &[&str] = &[
    "onPress",
    "onLongPress",
    "onPressIn",
    "onPressOut",
    "onSelect",
    "onClick",
];

const DEPRECATED_RN_CORE_MODULES: &[&str] = &[
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

const LEGACY_EXPO_PACKAGES: &[&str] = &[
    "expo-av",
    "expo-permissions",
    "expo-app-loading",
    "react-native-fast-image",
];

const JS_BOTTOM_SHEET_PACKAGES: &[&str] = &[
    "react-native-bottom-sheet",
    "react-native-modal-bottom-sheet",
    "react-native-raw-bottom-sheet",
    "react-native-modalize",
    "react-native-actions-sheet",
    "react-native-bottomsheet-reanimated",
    "@discord/bottom-sheet",
];

const PUBLIC_RN_ROOT_EXPORTS: &[&str] = &[
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

const LEGACY_SHADOW_PROPS: &[&str] = &[
    "shadowColor",
    "shadowOffset",
    "shadowOpacity",
    "shadowRadius",
    "elevation",
];

const TOUCHABLE_COMPONENTS: &[&str] = &[
    "TouchableOpacity",
    "TouchableHighlight",
    "TouchableWithoutFeedback",
    "TouchableNativeFeedback",
];

const DETOX_ELEMENT_ACTIONS: &[&str] = &[
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
                if !is_node_or_build_file
                    && let BindingPattern::ObjectPattern(_) = &decl.id
                    && let Some(init) = &decl.init
                    && is_process_env_expr(init)
                {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::ExpoNoNonInlinedEnv,
                        subject_name: subject_name.clone(),
                        message_id: "expoNoNonInlinedEnv",
                        target_name: "process.env".to_string(),
                        message: "Destructuring `process.env` isn't inlined by babel-preset-expo, so the values are `undefined` at runtime. Read each var via `process.env.EXPO_PUBLIC_NAME`.".to_string(),
                        loc: loc_from_line_starts(line_starts, decl.span.start),
                        span: ByteSpan {
                            start: decl.span.start,
                            end: decl.span.end,
                        },
                        autofix: None,
                    });
                }
            }
            AstKind::StaticMemberExpression(mem) => {
                if mem.property.name == "Platform"
                    && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
                    && is_namespace_import_from(program, obj_id.name.as_str(), "react-native")
                {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::RnPlatformShakingUseDirectImport,
                        subject_name: subject_name.clone(),
                        message_id: "rnPlatformShakingUseDirectImport",
                        target_name: "Platform".to_string(),
                        message: "Expo cannot tree-shake platform branches reached through the React Native namespace, so both platform paths stay in the bundle.".to_string(),
                        loc: loc_from_line_starts(line_starts, mem.span.start),
                        span: ByteSpan {
                            start: mem.span.start,
                            end: mem.span.end,
                        },
                        autofix: None,
                    });
                }
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

fn is_process_env_expr(expr: &Expression<'_>) -> bool {
    if let Expression::StaticMemberExpression(mem) = expr.without_parentheses()
        && mem.property.name == "env"
        && let Expression::Identifier(obj) = mem.object.without_parentheses()
    {
        obj.name == "process"
    } else {
        false
    }
}

fn is_namespace_import_from(program: &Program<'_>, local_name: &str, module_src: &str) -> bool {
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

fn is_named_import_from(
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

fn check_rn_import_rules(
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
                sites.push(SemanticRuleSite {
                    rule: RuleId::RnNoDeepImports,
                    subject_name: None,
                    message_id: "rnNoDeepImports",
                    target_name: src.to_string(),
                    message: format!(
                        "Deep import from \"{src}\" reaches into internal React Native paths; import \"{seg_stem}\" from \"react-native\" instead."
                    ),
                    loc: loc_from_line_starts(line_starts, imp.span.start),
                    span: ByteSpan {
                        start: imp.span.start,
                        end: imp.span.end,
                    },
                    autofix: None,
                });
            }
        }

        // 2. `rn-no-legacy-expo-packages`
        for &legacy_pkg in LEGACY_EXPO_PACKAGES {
            if src == legacy_pkg || src.starts_with(&format!("{legacy_pkg}/")) {
                sites.push(SemanticRuleSite {
                    rule: RuleId::RnNoLegacyExpoPackages,
                    subject_name: None,
                    message_id: "rnNoLegacyExpoPackages",
                    target_name: legacy_pkg.to_string(),
                    message: format!(
                        "Your users are exposed to unfixed bugs when \"{legacy_pkg}\" is no longer maintained."
                    ),
                    loc: loc_from_line_starts(line_starts, imp.span.start),
                    span: ByteSpan {
                        start: imp.span.start,
                        end: imp.span.end,
                    },
                    autofix: None,
                });
                break;
            }
        }

        // 3. `rn-bottom-sheet-prefer-native`
        if JS_BOTTOM_SHEET_PACKAGES.contains(&src) {
            sites.push(SemanticRuleSite {
                rule: RuleId::RnBottomSheetPreferNative,
                subject_name: None,
                message_id: "rnBottomSheetPreferNative",
                target_name: src.to_string(),
                message: format!(
                    "Users get JS-driven sheet gestures and presentation with {src}, instead of the platform-native formSheet behavior."
                ),
                loc: loc_from_line_starts(line_starts, imp.span.start),
                span: ByteSpan {
                    start: imp.span.start,
                    end: imp.span.end,
                },
                autofix: None,
            });
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
            sites.push(SemanticRuleSite {
                rule: RuleId::RnNoNonNativeNavigator,
                subject_name: None,
                message_id: "rnNoNonNativeNavigator",
                target_name: src.to_string(),
                message: format!(
                    "Users get JS-driven transitions and gestures from {src}, instead of platform-native navigation behavior."
                ),
                loc: loc_from_line_starts(line_starts, imp.span.start),
                span: ByteSpan {
                    start: imp.span.start,
                    end: imp.span.end,
                },
                autofix: None,
            });
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
                }
                let imported = sp.imported.name().as_str();
                let local = sp.local.name.as_str();

                if src == "react-native" && DEPRECATED_RN_CORE_MODULES.contains(&imported) {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::RnNoDeprecatedModules,
                        subject_name: None,
                        message_id: "rnNoDeprecatedModules",
                        target_name: imported.to_string(),
                        message: format!(
                            "Your users hit a crash from \"{imported}\", which was removed from react-native."
                        ),
                        loc: loc_from_line_starts(line_starts, sp.span.start),
                        span: ByteSpan {
                            start: sp.span.start,
                            end: sp.span.end,
                        },
                        autofix: None,
                    });
                }

                if src == "react-native" && imported == "PanResponder" {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::RnNoPanresponder,
                        subject_name: None,
                        message_id: "rnNoPanresponder",
                        target_name: "PanResponder".to_string(),
                        message: "PanResponder runs gesture handling on the JS thread, which stutters under load. Use react-native-gesture-handler (`Gesture.Pan()`) so gestures run on the native UI thread.".to_string(),
                        loc: loc_from_line_starts(line_starts, sp.span.start),
                        span: ByteSpan {
                            start: sp.span.start,
                            end: sp.span.end,
                        },
                        autofix: None,
                    });
                }

                if TOUCHABLE_COMPONENTS.contains(&imported) {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::RnPreferPressable,
                        subject_name: None,
                        message_id: "rnPreferPressable",
                        target_name: imported.to_string(),
                        message: format!(
                            "Your users miss <Pressable>'s flexible press feedback when you use {imported}, which is old & frozen."
                        ),
                        loc: loc_from_line_starts(line_starts, sp.span.start),
                        span: ByteSpan {
                            start: sp.span.start,
                            end: sp.span.end,
                        },
                        autofix: None,
                    });
                }

                if src == "react-native"
                    && imported == "Image"
                    && should_flag_rn_prefer_expo_image(semantic, local, source)
                {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::RnPreferExpoImage,
                        subject_name: None,
                        message_id: "rnPreferExpoImage",
                        target_name: "Image".to_string(),
                        message: "React Native's <Image> lacks disk caching and placeholders; prefer <Image> from expo-image.".to_string(),
                        loc: loc_from_line_starts(line_starts, sp.span.start),
                        span: ByteSpan {
                            start: sp.span.start,
                            end: sp.span.end,
                        },
                        autofix: None,
                    });
                }
                if src == "react-native" && imported == "Animated" {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::RnPreferReanimated,
                        subject_name: None,
                        message_id: "rnPreferReanimated",
                        target_name: "Animated".to_string(),
                        message: "Prefer `react-native-reanimated` over React Native's legacy `Animated` API so animations run on the UI thread.".to_string(),
                        loc: loc_from_line_starts(line_starts, sp.span.start),
                        span: ByteSpan {
                            start: sp.span.start,
                            end: sp.span.end,
                        },
                        autofix: None,
                    });
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
    reason = "Single-pass visitor for all React Native CallExpression rules"
)]
fn check_rn_call_rules(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    node_id: NodeId,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    is_detox_file: bool,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    // 1. `rn-animation-reaction-as-derived`
    if let Expression::Identifier(id) = call.callee.without_parentheses()
        && id.name == "useAnimatedReaction"
        && is_named_import_from(
            program,
            "useAnimatedReaction",
            "useAnimatedReaction",
            "react-native-reanimated",
        )
        && let Some(second_arg) = call.arguments.get(1).and_then(Argument::as_expression)
        && is_single_shared_value_copy(second_arg, source)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RnAnimationReactionAsDerived,
            subject_name: subject_name.clone(),
            message_id: "rnAnimationReactionAsDerived",
            target_name: "useAnimatedReaction".to_string(),
            message: "This useAnimatedReaction only copies one shared value into another, so it can miss Reanimated's derived-value dependency tracking.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 2. `rn-no-dimensions-get`
    if subject_name.is_some()
        && let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
        && mem.property.name == "get"
        && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
        && obj_id.name == "Dimensions"
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RnNoDimensionsGet,
            subject_name: subject_name.clone(),
            message_id: "rnNoDimensionsGet",
            target_name: "Dimensions.get".to_string(),
            message: "Dimensions.get() inside a component does not update when the window rotates or resizes; use useWindowDimensions() instead.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 3. `StyleSheet.create(...)` shadow rules (`rn-style-prefer-box-shadow`, `rn-no-legacy-shadow-styles`)
    if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
        && mem.property.name == "create"
        && let Expression::Identifier(obj_id) = mem.object.without_parentheses()
        && obj_id.name == "StyleSheet"
        && let Some(Argument::ObjectExpression(styles_obj)) = call.arguments.first()
    {
        for prop_kind in &styles_obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let Expression::ObjectExpression(style_def) = prop.value.without_parentheses() else {
                continue;
            };
            check_style_object_shadows(style_def, subject_name, line_starts, sites);
        }
    }

    // 4. Reanimated 4 migration rules (`rn-reanimated-4-*`)
    if let Expression::Identifier(id) = call.callee.without_parentheses() {
        let fn_name = id.name.as_str();
        if is_named_import_from(program, fn_name, fn_name, "react-native-reanimated") {
            if fn_name == "withSpring"
                && let Some(Argument::ObjectExpression(cfg_obj)) = call.arguments.get(1)
            {
                for prop_kind in &cfg_obj.properties {
                    let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                        continue;
                    };
                    let key_name = prop.key.static_name();
                    let Some(k) = key_name.as_ref().and_then(|n| n.as_str()) else {
                        continue;
                    };
                    if matches!(k, "restDisplacementThreshold" | "restSpeedThreshold") {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::RnReanimated4NoLegacySpringThresholds,
                            subject_name: subject_name.clone(),
                            message_id: "rnReanimated4NoLegacySpringThresholds",
                            target_name: k.to_string(),
                            message: format!(
                                "Reanimated 4 removed `{k}`; use the `energyThreshold` spring option instead."
                            ),
                            loc: loc_from_line_starts(line_starts, prop.span.start),
                            span: ByteSpan {
                                start: prop.span.start,
                                end: prop.span.end,
                            },
                            autofix: None,
                        });
                    }
                }
            }

            if matches!(
                fn_name,
                "useAnimatedGestureHandler"
                    | "useWorkletCallback"
                    | "combineTransition"
                    | "addWhitelistedNativeProps"
                    | "addWhitelistedUIProps"
            ) {
                sites.push(SemanticRuleSite {
                    rule: RuleId::RnReanimated4NoRemovedApi,
                    subject_name: subject_name.clone(),
                    message_id: "rnReanimated4NoRemovedApi",
                    target_name: fn_name.to_string(),
                    message: format!("Reanimated 4 removed `{fn_name}`; migrate to the Gesture API or Reanimated 4 replacement."),
                    loc: loc_from_line_starts(line_starts, call.span.start),
                    span: ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    },
                    autofix: None,
                });
            }

            if matches!(
                fn_name,
                "runOnUI" | "runOnJS" | "executeOnUIRuntimeSync" | "runOnRuntime"
            ) {
                sites.push(SemanticRuleSite {
                    rule: RuleId::RnReanimated4UseWorkletsScheduler,
                    subject_name: subject_name.clone(),
                    message_id: "rnReanimated4UseWorkletsScheduler",
                    target_name: fn_name.to_string(),
                    message: format!(
                        "For Reanimated 4, import the worklet scheduler replacement for `{fn_name}` from `react-native-worklets`."
                    ),
                    loc: loc_from_line_starts(line_starts, call.span.start),
                    span: ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }

    // 5. `rn-detox-missing-await`
    if is_detox_file
        && matches!(
            semantic.nodes().parent_kind(node_id),
            AstKind::ExpressionStatement(_)
        )
        && is_unawaited_detox_action(call, source)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RnDetoxMissingAwait,
            subject_name: subject_name.clone(),
            message_id: "rnDetoxMissingAwait",
            target_name: "detox".to_string(),
            message: "Detox actions and expectations return a Promise; prepend `await` so the test synchronizes properly.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }
    // 6. `rn-no-set-native-props`
    if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
        && mem.property.name == "setNativeProps"
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RnNoSetNativeProps,
            subject_name: subject_name.clone(),
            message_id: "rnNoSetNativeProps",
            target_name: "setNativeProps".to_string(),
            message: "Imperative `setNativeProps` bypasses React state and the New Architecture; use declarative props or Reanimated shared values.".to_string(),
            loc: loc_from_line_starts(line_starts, call.span.start),
            span: ByteSpan {
                start: call.span.start,
                end: call.span.end,
            },
            autofix: None,
        });
    }

    // 7. `rn-animate-layout-property`
    check_rn_animate_layout_property(semantic, call, subject_name, line_starts, sites);
}

fn is_single_shared_value_copy(reaction_fn: &Expression<'_>, _source: &str) -> bool {
    let single_expr = match reaction_fn.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) => match &arrow.body {
            ArrowFunctionBody::FunctionBody(body) => {
                if body.statements.len() != 1 {
                    return false;
                }
                if let Statement::ExpressionStatement(es) = &body.statements[0] {
                    Some(es.expression.without_parentheses())
                } else {
                    None
                }
            }
            _ => arrow
                .body
                .as_expression()
                .map(Expression::without_parentheses),
        },
        Expression::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return false;
            };
            if body.statements.len() != 1 {
                return false;
            }
            if let Statement::ExpressionStatement(es) = &body.statements[0] {
                Some(es.expression.without_parentheses())
            } else {
                None
            }
        }
        _ => None,
    };

    let Some(expr) = single_expr else {
        return false;
    };
    match expr {
        Expression::AssignmentExpression(assign) => {
            matches!(
                &assign.left,
                AssignmentTarget::StaticMemberExpression(mem)
                    if mem.property.name == "value"
                        && matches!(mem.object.without_parentheses(), Expression::Identifier(_))
            )
        }
        Expression::CallExpression(c) => {
            matches!(
                c.callee.without_parentheses(),
                Expression::StaticMemberExpression(mem)
                    if mem.property.name == "set" && c.arguments.len() == 1
            )
        }
        _ => false,
    }
}

fn check_rn_animate_layout_property(
    semantic: &Semantic<'_>,
    call: &CallExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    const RN_LAYOUT_PROPS: &[&str] = &[
        "width",
        "height",
        "top",
        "left",
        "right",
        "bottom",
        "padding",
        "paddingTop",
        "paddingBottom",
        "paddingLeft",
        "paddingRight",
        "paddingHorizontal",
        "paddingVertical",
        "margin",
        "marginTop",
        "marginBottom",
        "marginLeft",
        "marginRight",
        "marginHorizontal",
        "marginVertical",
        "flex",
        "flexGrow",
        "borderWidth",
        "gap",
    ];
    let is_use_animated_style = matches!(
        call.callee.without_parentheses(),
        Expression::Identifier(id) if id.name == "useAnimatedStyle"
    );
    if !is_use_animated_style {
        return;
    }
    let Some(first_arg) = call.arguments.first().and_then(Argument::as_expression) else {
        return;
    };
    let cb_span = first_arg.span();
    for (_, node) in semantic.nodes().iter_enumerated() {
        if !cb_span.contains_inclusive(node.span()) {
            continue;
        }
        let AstKind::ObjectProperty(prop) = node.kind() else {
            continue;
        };
        let Some(key_name) = prop.key.static_name() else {
            continue;
        };
        let Some(k) = key_name.as_str() else {
            continue;
        };
        if RN_LAYOUT_PROPS.contains(&k) {
            sites.push(SemanticRuleSite {
                rule: RuleId::RnAnimateLayoutProperty,
                subject_name: subject_name.clone(),
                message_id: "rnAnimateLayoutProperty",
                target_name: k.to_string(),
                message: format!(
                    "Animating layout property `{k}` inside `useAnimatedStyle` triggers Yoga layout recalculations on every frame; animate `transform` or `opacity` instead."
                ),
                loc: loc_from_line_starts(line_starts, prop.span.start),
                span: ByteSpan {
                    start: prop.span.start,
                    end: prop.span.end,
                },
                autofix: None,
            });
        }
    }
}

fn is_unawaited_detox_action(call: &CallExpression<'_>, source: &str) -> bool {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return false;
    };
    let method = mem.property.name.as_str();
    let call_text = call.span.source_text(source).trim();
    if DETOX_ELEMENT_ACTIONS.contains(&method) && call_text.starts_with("element(") {
        return true;
    }
    if method == "withTimeout" && call_text.starts_with("waitFor(") {
        return true;
    }
    if (call_text.starts_with("expect(element(") || call_text.starts_with("expect(web("))
        && method.starts_with("to")
    {
        return true;
    }
    false
}

fn check_style_object_shadows(
    style_obj: &ObjectExpression<'_>,
    subject_name: &Option<String>,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let mut shadow_keys = Vec::new();
    for prop_kind in &style_obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
            continue;
        };
        let key_name = prop.key.static_name();
        let Some(k) = key_name.as_ref().and_then(|n| n.as_str()) else {
            continue;
        };
        if LEGACY_SHADOW_PROPS.contains(&k) {
            shadow_keys.push((k.to_string(), prop.span));
        }
    }

    if shadow_keys.is_empty() {
        return;
    }

    let quoted: Vec<String> = shadow_keys
        .iter()
        .map(|(k, _)| format!("\"{k}\""))
        .collect();
    sites.push(SemanticRuleSite {
        rule: RuleId::RnNoLegacyShadowStyles,
        subject_name: subject_name.clone(),
        message_id: "rnNoLegacyShadowStyles",
        target_name: shadow_keys[0].0.clone(),
        message: format!(
            "Shadow style{} {} only work on one platform, so your users on the other see no shadow.",
            if shadow_keys.len() > 1 { "s" } else { "" },
            quoted.join(", ")
        ),
        loc: loc_from_line_starts(line_starts, style_obj.span.start),
        span: ByteSpan {
            start: style_obj.span.start,
            end: style_obj.span.end,
        },
        autofix: None,
    });

    let first_span = shadow_keys[0].1;
    sites.push(SemanticRuleSite {
        rule: RuleId::RnStylePreferBoxShadow,
        subject_name: subject_name.clone(),
        message_id: "rnStylePreferBoxShadow",
        target_name: shadow_keys[0].0.clone(),
        message: "Prefer the standard CSS `boxShadow` string over legacy platform-specific shadow properties.".to_string(),
        loc: loc_from_line_starts(line_starts, first_span.start),
        span: ByteSpan {
            start: first_span.start,
            end: first_span.end,
        },
        autofix: None,
    });
}

#[expect(
    clippy::too_many_arguments,
    reason = "Single-pass JSXElement visitor for all React Native JSX rules"
)]
fn check_rn_jsx_element_rules(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    _node_id: NodeId,
    jsx_el: &JSXElement<'_>,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;
    let el_name = opening.name.span().source_text(source).trim();

    // 1. Style attribute legacy shadow check
    for attr_item in &opening.attributes {
        let Some(attr) = attr_item.as_attribute() else {
            continue;
        };
        let JSXAttributeName::Identifier(attr_id) = &attr.name else {
            continue;
        };
        let attr_name = attr_id.name.as_str();
        if (attr_name == "style" || attr_name.ends_with("Style"))
            && let Some(JSXAttributeValue::ExpressionContainer(container)) = &attr.value
            && let Some(expr) = container.expression.as_expression()
        {
            match expr.without_parentheses() {
                Expression::ObjectExpression(obj) => {
                    check_style_object_shadows(obj, subject_name, line_starts, sites);
                }
                Expression::ArrayExpression(arr) => {
                    for elem in &arr.elements {
                        if let Some(e) = elem.as_expression()
                            && let Expression::ObjectExpression(obj) = e.without_parentheses()
                        {
                            check_style_object_shadows(obj, subject_name, line_starts, sites);
                        }
                    }
                    if arr.elements.len() == 1
                        && !matches!(
                            &arr.elements[0],
                            oxc_ast::ast::ArrayExpressionElement::SpreadElement(_)
                        )
                    {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::RnNoSingleElementStyleArray,
                            subject_name: subject_name.clone(),
                            message_id: "rnNoSingleElementStyleArray",
                            target_name: attr_name.to_string(),
                            message: format!(
                                "Single-element style array `{attr_name}={{[...]}}` allocates an unnecessary array wrapper; pass the style value directly."
                            ),
                            loc: loc_from_line_starts(line_starts, attr.span.start),
                            span: ByteSpan {
                                start: attr.span.start,
                                end: attr.span.end,
                            },
                            autofix: None,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    // 2. `rn-no-falsy-and-render`: `{items.length && <Text>...}`
    for child in &jsx_el.children {
        if let JSXChild::ExpressionContainer(container) = child
            && let JSXExpression::LogicalExpression(logical) = &container.expression
            && logical.operator == LogicalOperator::And
            && is_likely_numeric_falsy_lhs(&logical.left, source)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::RnNoFalsyAndRender,
                subject_name: subject_name.clone(),
                message_id: "rnNoFalsyAndRender",
                target_name: logical.left.span().source_text(source).to_string(),
                message: "If the left-hand side of `&&` evaluates to `0`, React Native renders a bare number outside `<Text>` and crashes.".to_string(),
                loc: loc_from_line_starts(line_starts, logical.span.start),
                span: ByteSpan {
                    start: logical.span.start,
                    end: logical.span.end,
                },
                autofix: None,
            });
        }
    }

    // 3. `rn-no-image-children`
    if el_name == "Image"
        && is_named_import_from(program, "Image", "Image", "react-native")
        && jsx_el.children.iter().any(is_meaningful_jsx_child)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RnNoImageChildren,
            subject_name: subject_name.clone(),
            message_id: "rnNoImageChildren",
            target_name: "Image".to_string(),
            message: "React Native's <Image> does not render children, so this content silently disappears. Use <ImageBackground> to layer content over an image.".to_string(),
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }

    // 4. `rn-bottom-sheet-*`
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
                    sites.push(SemanticRuleSite {
                        rule: RuleId::RnBottomSheetNoIgnoredScrollProp,
                        subject_name: subject_name.clone(),
                        message_id: "rnBottomSheetNoIgnoredScrollProp",
                        target_name: prop_name.to_string(),
                        message: format!(
                            "BottomSheetScrollView ignores `{prop_name}`, so this prop cannot affect scrolling. Remove it or handle the behavior outside the scrollable."
                        ),
                        loc: loc_from_line_starts(line_starts, attr.span.start),
                        span: ByteSpan {
                            start: attr.span.start,
                            end: attr.span.end,
                        },
                        autofix: None,
                    });
                }
            }
        }
    }

    if matches!(el_name, "BottomSheet" | "BottomSheetModal") {
        // `rn-bottom-sheet-no-state-in-on-animate`
        if let Some(on_animate_attr) = find_jsx_attr(opening, "onAnimate")
            && let Some(setter_span) = find_state_setter_in_attr(semantic, on_animate_attr)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::RnBottomSheetNoStateInOnAnimate,
                subject_name: subject_name.clone(),
                message_id: "rnBottomSheetNoStateInOnAnimate",
                target_name: "onAnimate".to_string(),
                message: "This onAnimate handler starts a React state update as the Bottom Sheet begins moving, adding render work to the transition. Use animatedIndex or animatedPosition for animation-coupled UI.".to_string(),
                loc: loc_from_line_starts(line_starts, setter_span.start),
                span: ByteSpan {
                    start: setter_span.start,
                    end: setter_span.end,
                },
                autofix: None,
            });
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
                sites.push(SemanticRuleSite {
                    rule: RuleId::RnBottomSheetUseIntegratedScrollable,
                    subject_name: subject_name.clone(),
                    message_id: "rnBottomSheetUseIntegratedScrollable",
                    target_name: child_name.to_string(),
                    message: format!(
                        "React Native's `{child_name}` does not coordinate gestures with this Bottom Sheet. Use `BottomSheet{child_name}` from @gorhom/bottom-sheet."
                    ),
                    loc: loc_from_line_starts(line_starts, child_el.opening_element.span.start),
                    span: ByteSpan {
                        start: child_el.opening_element.span.start,
                        end: child_el.opening_element.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }

    // 5. ScrollView & List rules
    check_scrollview_and_list_jsx_rules(
        program,
        semantic,
        jsx_el,
        el_name,
        subject_name,
        source,
        line_starts,
        sites,
    );

    // 6. `rn-prefer-pressable-over-gesture-detector` & `rn-pressable-shared-value-mutation`
    check_gesture_and_pressable_jsx_rules(
        semantic,
        jsx_el,
        el_name,
        subject_name,
        source,
        line_starts,
        sites,
    );
    // 7. `rn-prefer-content-inset-adjustment`
    if el_name == "SafeAreaView"
        && jsx_el.children.iter().any(|c| {
            if let JSXChild::Element(child_el) = c {
                let child_name = child_el
                    .opening_element
                    .name
                    .span()
                    .source_text(source)
                    .trim();
                SCROLL_CONTAINER_NAMES.contains(&child_name)
            } else {
                false
            }
        })
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RnPreferContentInsetAdjustment,
            subject_name: subject_name.clone(),
            message_id: "rnPreferContentInsetAdjustment",
            target_name: "SafeAreaView".to_string(),
            message: "Prefer `contentInsetAdjustmentBehavior=\"automatic\"` on the scrollable container instead of wrapping it in `<SafeAreaView>`.".to_string(),
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Evaluates ScrollView and virtualized list JSX rules in one pass"
)]
fn check_scrollview_and_list_jsx_rules(
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

    // `onScroll` state setter (`rn-no-scroll-state`)
    if let Some(on_scroll_attr) = find_jsx_attr(opening, "onScroll")
        && let Some(setter_span) = find_state_setter_in_attr(semantic, on_scroll_attr)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RnNoScrollState,
            subject_name: subject_name.clone(),
            message_id: "rnNoScrollState",
            target_name: "onScroll".to_string(),
            message: "Updating React state inside onScroll triggers a re-render on every scroll frame; use a Reanimated shared value or ref instead.".to_string(),
            loc: loc_from_line_starts(line_starts, setter_span.start),
            span: ByteSpan {
                start: setter_span.start,
                end: setter_span.end,
            },
            autofix: None,
        });
    }

    // `ScrollView` mapped list (`rn-no-scrollview-mapped-list`)
    if el_name == "ScrollView" {
        for child in &jsx_el.children {
            if let JSXChild::ExpressionContainer(container) = child
                && let Some(expr) = container.expression.as_expression()
                && let Expression::CallExpression(call) = expr.without_parentheses()
                && let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                && matches!(mem.property.name.as_str(), "map" | "flatMap")
                && !matches!(mem.object.without_parentheses(), Expression::ArrayExpression(arr) if arr.elements.len() <= 10)
            {
                sites.push(SemanticRuleSite {
                    rule: RuleId::RnNoScrollviewMappedList,
                    subject_name: subject_name.clone(),
                    message_id: "rnNoScrollviewMappedList",
                    target_name: "ScrollView".to_string(),
                    message: "Rendering a dynamic .map() list inside <ScrollView> mounts every item at once; use FlashList, LegendList, or FlatList instead.".to_string(),
                    loc: loc_from_line_starts(line_starts, call.span.start),
                    span: ByteSpan {
                        start: call.span.start,
                        end: call.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }

    // `contentContainerStyle` rules (`rn-scrollview-flex-in-content-container`, `rn-scrollview-dynamic-padding`)
    if SCROLL_CONTAINER_NAMES.contains(&el_name)
        && let Some(ccs_attr) = find_jsx_attr(opening, "contentContainerStyle")
        && let Some(JSXAttributeValue::ExpressionContainer(container)) = &ccs_attr.value
        && let Some(expr) = container.expression.as_expression()
        && let Expression::ObjectExpression(ccs_obj) = expr.without_parentheses()
    {
        let has_explicit_flex_grow_or_basis = ccs_obj.properties.iter().any(|p| {
            let ObjectPropertyKind::ObjectProperty(prop) = p else {
                return false;
            };
            matches!(
                prop.key.static_name().as_ref().and_then(|n| n.as_str()),
                Some("flexGrow" | "flexBasis")
            )
        });

        for prop_kind in &ccs_obj.properties {
            let ObjectPropertyKind::ObjectProperty(prop) = prop_kind else {
                continue;
            };
            let key_name = prop.key.static_name();
            let Some(k) = key_name.as_ref().and_then(|n| n.as_str()) else {
                continue;
            };
            if k == "flex" && !has_explicit_flex_grow_or_basis {
                sites.push(SemanticRuleSite {
                    rule: RuleId::RnScrollviewFlexInContentContainer,
                    subject_name: subject_name.clone(),
                    message_id: "rnScrollviewFlexInContentContainer",
                    target_name: "flex".to_string(),
                    message: "Using `flex` on `contentContainerStyle` sets `flexBasis: 0` and clips scrolling when content overflows; use `flexGrow: 1` instead.".to_string(),
                    loc: loc_from_line_starts(line_starts, prop.span.start),
                    span: ByteSpan {
                        start: prop.span.start,
                        end: prop.span.end,
                    },
                    autofix: None,
                });
            }
            if matches!(k, "paddingBottom" | "paddingTop")
                && !is_static_style_value(semantic, &prop.value)
            {
                sites.push(SemanticRuleSite {
                    rule: RuleId::RnScrollviewDynamicPadding,
                    subject_name: subject_name.clone(),
                    message_id: "rnScrollviewDynamicPadding",
                    target_name: k.to_string(),
                    message: format!(
                        "Dynamic `{k}` on `contentContainerStyle` relayouts the entire scroll content on every change; use `contentInset` instead."
                    ),
                    loc: loc_from_line_starts(line_starts, prop.span.start),
                    span: ByteSpan {
                        start: prop.span.start,
                        end: prop.span.end,
                    },
                    autofix: None,
                });
            }
        }
    }

    // List component rules
    if !REACT_NATIVE_LIST_COMPONENTS.contains(&el_name) {
        return;
    }

    // `rn-list-data-mapped`
    if let Some(data_attr) = find_jsx_attr(opening, "data")
        && let Some(JSXAttributeValue::ExpressionContainer(container)) = &data_attr.value
        && let Some(expr) = container.expression.as_expression()
        && is_fresh_array_data_expr(expr)
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RnListDataMapped,
            subject_name: subject_name.clone(),
            message_id: "rnListDataMapped",
            target_name: "data".to_string(),
            message: format!(
                "Passing a fresh array expression to `data` on `<{el_name}>` invalidates row memoization on every render; wrap the derived array in `useMemo`."
            ),
            loc: loc_from_line_starts(line_starts, data_attr.span.start),
            span: ByteSpan {
                start: data_attr.span.start,
                end: data_attr.span.end,
            },
            autofix: None,
        });
    }

    let is_recycler = matches!(
        el_name,
        "FlashList"
            | "AnimatedFlashList"
            | "LegendList"
            | "AnimatedLegendList"
            | "KeyboardAwareLegendList"
            | "KeyboardAvoidingLegendList"
    ) && (is_named_import_from(program, el_name, el_name, "@shopify/flash-list")
        || is_named_import_from(program, el_name, el_name, "@legendapp/list"));

    // `rn-list-missing-estimated-item-size`
    if is_recycler
        && find_jsx_attr(opening, "estimatedItemSize").is_none()
        && find_jsx_attr(opening, "estimatedListSize").is_none()
    {
        sites.push(SemanticRuleSite {
            rule: RuleId::RnListMissingEstimatedItemSize,
            subject_name: subject_name.clone(),
            message_id: "rnListMissingEstimatedItemSize",
            target_name: el_name.to_string(),
            message: format!(
                "`<{el_name}>` is missing `estimatedItemSize`, which can cause blank cells to flash during fast scrolling."
            ),
            loc: loc_from_line_starts(line_starts, opening.span.start),
            span: ByteSpan {
                start: opening.span.start,
                end: opening.span.end,
            },
            autofix: None,
        });
    }

    // `renderItem` rules
    for &prop_name in RENDER_ITEM_PROP_NAMES {
        let Some(render_attr) = find_jsx_attr(opening, prop_name) else {
            continue;
        };
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &render_attr.value else {
            continue;
        };
        let Some(expr) = container.expression.as_expression() else {
            continue;
        };
        let fn_expr = expr.without_parentheses();
        if !matches!(
            fn_expr,
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
        ) {
            continue;
        }
        let fn_span = fn_expr.span();

        // 1. `rn-no-inline-flatlist-renderitem`
        if prop_name == "renderItem" {
            sites.push(SemanticRuleSite {
                rule: RuleId::RnNoInlineFlatlistRenderitem,
                subject_name: subject_name.clone(),
                message_id: "rnNoInlineFlatlistRenderitem",
                target_name: el_name.to_string(),
                message: format!(
                    "Your users see extra row work when renderItem on <{el_name}> is rebuilt every time the screen redraws."
                ),
                loc: loc_from_line_starts(line_starts, fn_span.start),
                span: ByteSpan {
                    start: fn_span.start,
                    end: fn_span.end,
                },
                autofix: None,
            });
        }

        // 2. `rn-list-recyclable-without-types`
        if is_recycler
            && prop_name == "renderItem"
            && find_jsx_attr(opening, "getItemType").is_none()
            && render_item_has_heterogeneous_roots(semantic, fn_span, source)
        {
            sites.push(SemanticRuleSite {
                rule: RuleId::RnListRecyclableWithoutTypes,
                subject_name: subject_name.clone(),
                message_id: "rnListRecyclableWithoutTypes",
                target_name: el_name.to_string(),
                message: format!(
                    "`<{el_name}>` `renderItem` returns multiple root component types without `getItemType`, causing recycled views to mismatch."
                ),
                loc: loc_from_line_starts(line_starts, render_attr.span.start),
                span: ByteSpan {
                    start: render_attr.span.start,
                    end: render_attr.span.end,
                },
                autofix: None,
            });
        }

        // Scan JSX elements inside `renderItem` for:
        // - `rn-list-callback-per-row`
        // - `rn-no-inline-object-in-list-item`
        // - `rn-no-renderitem-key`
        let mut reported_key = false;
        for (_, inner_node) in semantic.nodes().iter_enumerated() {
            let AstKind::JSXOpeningElement(inner_open) = inner_node.kind() else {
                continue;
            };
            if !fn_span.contains_inclusive(inner_open.span) {
                continue;
            }
            for attr_item in &inner_open.attributes {
                let Some(attr) = attr_item.as_attribute() else {
                    continue;
                };
                let JSXAttributeName::Identifier(attr_id) = &attr.name else {
                    continue;
                };
                let k = attr_id.name.as_str();
                if k == "key" && !reported_key {
                    reported_key = true;
                    sites.push(SemanticRuleSite {
                        rule: RuleId::RnNoRenderitemKey,
                        subject_name: subject_name.clone(),
                        message_id: "rnNoRenderitemKey",
                        target_name: "key".to_string(),
                        message: "A `key` on the JSX returned from `renderItem` is ignored by React Native lists; use `keyExtractor` on the list instead.".to_string(),
                        loc: loc_from_line_starts(line_starts, attr.span.start),
                        span: ByteSpan {
                            start: attr.span.start,
                            end: attr.span.end,
                        },
                        autofix: None,
                    });
                }
                if let Some(JSXAttributeValue::ExpressionContainer(c)) = &attr.value
                    && let Some(val_expr) = c.expression.as_expression()
                {
                    let unwrapped = val_expr.without_parentheses();
                    if LIST_ROW_PRESS_PROPS.contains(&k)
                        && matches!(
                            unwrapped,
                            Expression::ArrowFunctionExpression(_)
                                | Expression::FunctionExpression(_)
                        )
                    {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::RnListCallbackPerRow,
                            subject_name: subject_name.clone(),
                            message_id: "rnListCallbackPerRow",
                            target_name: k.to_string(),
                            message: format!(
                                "Inline `{k}` closure inside `{prop_name}` allocates a new function for every row on every render."
                            ),
                            loc: loc_from_line_starts(line_starts, unwrapped.span().start),
                            span: ByteSpan {
                                start: unwrapped.span().start,
                                end: unwrapped.span().end,
                            },
                            autofix: None,
                        });
                    }
                    if matches!(unwrapped, Expression::ObjectExpression(_)) {
                        sites.push(SemanticRuleSite {
                            rule: RuleId::RnNoInlineObjectInListItem,
                            subject_name: subject_name.clone(),
                            message_id: "rnNoInlineObjectInListItem",
                            target_name: k.to_string(),
                            message: format!(
                                "Inline object literal on `{k}` inside `{prop_name}` allocates a new reference per row."
                            ),
                            loc: loc_from_line_starts(line_starts, unwrapped.span().start),
                            span: ByteSpan {
                                start: unwrapped.span().start,
                                end: unwrapped.span().end,
                            },
                            autofix: None,
                        });
                    }
                }
            }
        }
    }
}

fn check_gesture_and_pressable_jsx_rules(
    semantic: &Semantic<'_>,
    jsx_el: &JSXElement<'_>,
    el_name: &str,
    subject_name: &Option<String>,
    source: &str,
    line_starts: &[u32],
    sites: &mut Vec<SemanticRuleSite>,
) {
    let opening = &jsx_el.opening_element;

    // 1. `rn-prefer-pressable-over-gesture-detector`
    if el_name == "GestureDetector"
        && let Some(gesture_attr) = find_jsx_attr(opening, "gesture")
        && let Some(JSXAttributeValue::ExpressionContainer(container)) = &gesture_attr.value
        && let Some(expr) = container.expression.as_expression()
    {
        let gesture_text = match expr.without_parentheses() {
            Expression::Identifier(ident) => ident
                .reference_id
                .get()
                .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
                .and_then(|s| {
                    let decl_id = semantic.scoping().symbol_declaration(s);
                    if let AstKind::VariableDeclarator(d) = semantic.nodes().kind(decl_id) {
                        d.init.as_ref().map(|i| i.span().source_text(source))
                    } else {
                        None
                    }
                })
                .unwrap_or_default(),
            other => other.span().source_text(source),
        };

        if gesture_text.contains("Gesture.Tap()") && !gesture_text.contains("numberOfTaps(") {
            sites.push(SemanticRuleSite {
                rule: RuleId::RnPreferPressableOverGestureDetector,
                subject_name: subject_name.clone(),
                message_id: "rnPreferPressableOverGestureDetector",
                target_name: "GestureDetector".to_string(),
                message: "Simple single-tap `Gesture.Tap()` inside `<GestureDetector>` adds native handler registration overhead; use `<Pressable>` instead.".to_string(),
                loc: loc_from_line_starts(line_starts, opening.span.start),
                span: ByteSpan {
                    start: opening.span.start,
                    end: opening.span.end,
                },
                autofix: None,
            });
        }
    }

    // 2. `rn-pressable-shared-value-mutation`
    if (el_name == "Pressable" || TOUCHABLE_COMPONENTS.contains(&el_name))
        && source.contains("useSharedValue(")
    {
        for prop_name in ["onPress", "onPressIn", "onPressOut", "onLongPress"] {
            if let Some(attr) = find_jsx_attr(opening, prop_name) {
                let attr_text = attr.span.source_text(source);
                if attr_text.contains(".value =") || attr_text.contains(".value=") {
                    sites.push(SemanticRuleSite {
                        rule: RuleId::RnPressableSharedValueMutation,
                        subject_name: subject_name.clone(),
                        message_id: "rnPressableSharedValueMutation",
                        target_name: prop_name.to_string(),
                        message: "Mutating a Reanimated shared value inside a Pressable JS handler crosses the bridge on press; use GestureDetector + Gesture.Tap() on the UI thread.".to_string(),
                        loc: loc_from_line_starts(line_starts, attr.span.start),
                        span: ByteSpan {
                            start: attr.span.start,
                            end: attr.span.end,
                        },
                        autofix: None,
                    });
                    break;
                }
            }
        }
    }
}

fn find_jsx_attr<'a>(
    opening: &'a oxc_ast::ast::JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a oxc_ast::ast::JSXAttribute<'a>> {
    for item in &opening.attributes {
        let Some(attr) = item.as_attribute() else {
            continue;
        };
        if let JSXAttributeName::Identifier(id) = &attr.name
            && id.name.as_str() == name
        {
            return Some(attr);
        }
    }
    None
}

fn find_state_setter_in_attr(
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

fn is_static_style_value(semantic: &Semantic<'_>, expr: &Expression<'_>) -> bool {
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

fn is_fresh_array_data_expr(expr: &Expression<'_>) -> bool {
    match expr.without_parentheses() {
        Expression::ArrayExpression(arr) => !arr.elements.is_empty(),
        Expression::CallExpression(call) => {
            if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() {
                matches!(
                    mem.property.name.as_str(),
                    "map"
                        | "filter"
                        | "slice"
                        | "concat"
                        | "flat"
                        | "flatMap"
                        | "toSorted"
                        | "toReversed"
                        | "toSpliced"
                )
            } else {
                false
            }
        }
        _ => false,
    }
}

fn render_item_has_heterogeneous_roots(
    semantic: &Semantic<'_>,
    fn_span: Span,
    source: &str,
) -> bool {
    let mut root_names: HashSet<String> = HashSet::new();
    for (node_id, node) in semantic.nodes().iter_enumerated() {
        let AstKind::JSXElement(jsx_el) = node.kind() else {
            continue;
        };
        if !fn_span.contains_inclusive(jsx_el.span) {
            continue;
        }
        // Only count top-level JSX elements inside `fn_span` (no ancestor JSXElement inside `fn_span`)
        let has_jsx_parent_in_fn = semantic.nodes().ancestor_ids(node_id).any(|anc_id| {
            let anc_span = semantic.nodes().get_node(anc_id).span();
            fn_span.contains_inclusive(anc_span)
                && matches!(semantic.nodes().kind(anc_id), AstKind::JSXElement(_))
        });
        if has_jsx_parent_in_fn {
            continue;
        }
        let name = jsx_el
            .opening_element
            .name
            .span()
            .source_text(source)
            .trim()
            .to_string();
        root_names.insert(name);
    }
    root_names.len() >= 2
}

fn is_likely_numeric_falsy_lhs(expr: &Expression<'_>, source: &str) -> bool {
    match expr.without_parentheses() {
        Expression::StaticMemberExpression(mem) => {
            matches!(
                mem.property.name.as_str(),
                "length" | "size" | "count" | "total" | "index" | "width" | "height"
            )
        }
        Expression::Identifier(id) => {
            let name = id.name.as_str();
            let lower = name.to_ascii_lowercase();
            (lower == "count"
                || lower.ends_with("count")
                || lower == "length"
                || lower.ends_with("length")
                || lower == "total"
                || lower == "index"
                || lower == "amount"
                || lower == "num")
                && !lower.starts_with("is")
                && !lower.starts_with("has")
                && !lower.starts_with("can")
                && !lower.starts_with("should")
        }
        _ => {
            let text = expr.span().source_text(source).trim();
            text.ends_with(".length") || text.ends_with(".size") || text.ends_with(".count")
        }
    }
}

fn is_meaningful_jsx_child(child: &JSXChild<'_>) -> bool {
    match child {
        JSXChild::Element(_) | JSXChild::Fragment(_) => true,
        JSXChild::Text(t) => !t.value.trim().is_empty(),
        JSXChild::ExpressionContainer(c) => !matches!(
            &c.expression,
            JSXExpression::EmptyExpression(_)
                | JSXExpression::NullLiteral(_)
                | JSXExpression::BooleanLiteral(_)
        ),
        JSXChild::Spread(_) => true,
    }
}

/// Evaluates all React Native and Expo project-level configuration checks across [`WorkspacePackage`]s.
pub(crate) fn evaluate_react_native_and_expo_project_checks(
    graph: &ProjectGraph,
    packages: &[WorkspacePackage],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if !graph.has_manifests {
        return;
    }

    for pkg in packages {
        let is_rule_enabled = |rule: RuleId| -> Option<RuleSeverity> {
            if let Some(explicit) = enabled_rules
                && !explicit.contains(&rule)
            {
                return None;
            }
            let has_explicit = enabled_rules.is_some_and(|list| list.contains(&rule));
            if !has_explicit && !pkg.capability_gate.allows_rule(rule.metadata()) {
                return None;
            }
            if has_explicit {
                Some(
                    pkg.config
                        .effective_severity(rule)
                        .unwrap_or(rule.metadata().default_severity),
                )
            } else {
                pkg.config.effective_severity(rule)
            }
        };

        if pkg.capability_gate.has(Capability::ReactNative) {
            check_rn_package_configs(graph, pkg, &is_rule_enabled, out);
        }
        if pkg.capability_gate.has(Capability::Expo) {
            check_expo_package_configs(graph, pkg, &is_rule_enabled, out);
        }
    }
}

fn find_manifest_in_pkg<'a>(
    graph: &'a ProjectGraph,
    pkg_root: &Path,
    rel_name: &str,
) -> Option<(PathBuf, &'a str)> {
    let candidate = if pkg_root == Path::new(".") || pkg_root.as_os_str().is_empty() {
        PathBuf::from(rel_name)
    } else {
        pkg_root.join(rel_name)
    };
    if let Some((k, v)) = graph.manifests.get_key_value(&candidate) {
        return Some((k.clone(), v.as_str()));
    }
    graph
        .manifests
        .iter()
        .find(|(p, _)| {
            p.ends_with(rel_name) && (pkg_root == Path::new(".") || p.starts_with(pkg_root))
        })
        .map(|(k, v)| (k.clone(), v.as_str()))
}

fn check_rn_package_configs<F>(
    graph: &ProjectGraph,
    pkg: &WorkspacePackage,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let pkg_json_entry = find_manifest_in_pkg(graph, &pkg.root_dir, "package.json");
    let pkg_json_val: Option<Value> = pkg_json_entry
        .as_ref()
        .and_then(|(_, txt)| serde_json::from_str::<Value>(&strip_jsonc(txt)).ok());
    let pkg_json_path = pkg_json_entry
        .map(|(p, _)| p)
        .unwrap_or_else(|| pkg.root_dir.join("package.json"));

    // 1. `rn-library-react-in-dependencies`
    if let Some(sev) = is_rule_enabled(RuleId::RnLibraryReactInDependencies)
        && let Some(val) = &pkg_json_val
        && val
            .get("react-native-builder-bob")
            .is_some_and(Value::is_object)
        && let Some(deps) = val.get("dependencies").and_then(Value::as_object)
    {
        let mut misplaced = Vec::new();
        for name in ["react", "react-native"] {
            if deps.contains_key(name) {
                misplaced.push(format!("\"{name}\""));
            }
        }
        if !misplaced.is_empty() {
            push_project_diagnostic(
                out,
                pkg_json_path.clone(),
                RuleId::RnLibraryReactInDependencies,
                sev,
                "rnLibraryReactInDependencies",
                "dependencies",
                format!(
                    "This react-native-builder-bob library lists {} in `dependencies` — move them to `peerDependencies` so a second copy is not bundled into consumer apps.",
                    misplaced.join(" and ")
                ),
            );
        }
    }

    // 2. Babel config checks (`rn-no-metro-babel-preset`, `rn-no-metro-babel-runtime-version`,
    //    `rn-react-compiler-plugin-first`, `rn-reanimated-worklets-plugin-last`)
    let babel_files = [
        "babel.config.js",
        "babel.config.cjs",
        "babel.config.mjs",
        "babel.config.ts",
        "babel.config.json",
        ".babelrc",
        ".babelrc.js",
        ".babelrc.json",
    ];
    for babel_name in babel_files {
        let Some((babel_path, babel_src)) = find_manifest_in_pkg(graph, &pkg.root_dir, babel_name)
        else {
            continue;
        };

        let rn_minor = pkg
            .capability_gate
            .dependencies
            .get("react-native")
            .and_then(|v| parse_rn_minor_version(v));
        let has_legacy_preset_dep = pkg
            .capability_gate
            .dependencies
            .contains_key("metro-react-native-babel-preset");

        if rn_minor.is_some_and(|m| m >= 73)
            && !has_legacy_preset_dep
            && (babel_src.contains("'module:metro-react-native-babel-preset'")
                || babel_src.contains("\"module:metro-react-native-babel-preset\""))
            && let Some(sev) = is_rule_enabled(RuleId::RnNoMetroBabelPreset)
        {
            push_project_diagnostic(
                out,
                babel_path.clone(),
                RuleId::RnNoMetroBabelPreset,
                sev,
                "rnNoMetroBabelPreset",
                "module:metro-react-native-babel-preset",
                "`module:metro-react-native-babel-preset` was renamed to `@react-native/babel-preset` and is no longer installed by React Native 0.73+.".to_string(),
            );
        }

        if (babel_src.contains("'module:@react-native/babel-preset'")
            || babel_src.contains("\"module:@react-native/babel-preset\""))
            && !has_enable_babel_runtime_version(babel_src)
            && let Some(sev) = is_rule_enabled(RuleId::RnNoMetroBabelRuntimeVersion)
        {
            push_project_diagnostic(
                out,
                babel_path.clone(),
                RuleId::RnNoMetroBabelRuntimeVersion,
                sev,
                "rnNoMetroBabelRuntimeVersion",
                "enableBabelRuntime",
                "`module:@react-native/babel-preset` has no `enableBabelRuntime` version, so Babel runtime helpers can be duplicated across files.".to_string(),
            );
        }

        // Static plugin order check
        if let Some(plugins) = extract_static_babel_plugins(babel_src) {
            if let Some(compiler_idx) = plugins
                .iter()
                .position(|p| p == "babel-plugin-react-compiler" || p == "react-compiler")
                && compiler_idx > 0
                && let Some(sev) = is_rule_enabled(RuleId::RnReactCompilerPluginFirst)
            {
                push_project_diagnostic(
                    out,
                    babel_path.clone(),
                    RuleId::RnReactCompilerPluginFirst,
                    sev,
                    "rnReactCompilerPluginFirst",
                    "babel-plugin-react-compiler",
                    "The React Compiler Babel plugin is not first in `plugins`, so an earlier transform can alter component code before the compiler analyzes it.".to_string(),
                );
            }

            let reanimated_major = pkg
                .capability_gate
                .dependencies
                .get("react-native-reanimated")
                .and_then(|v| parse_major_version(v));
            if reanimated_major.is_some_and(|m| m >= 4)
                && let Some(sev) = is_rule_enabled(RuleId::RnReanimatedWorkletsPluginLast)
            {
                if plugins
                    .iter()
                    .any(|p| p == "react-native-reanimated/plugin")
                {
                    push_project_diagnostic(
                        out,
                        babel_path.clone(),
                        RuleId::RnReanimatedWorkletsPluginLast,
                        sev,
                        "rnReanimatedWorkletsPluginLast",
                        "react-native-reanimated/plugin",
                        "This Reanimated 4 project still uses `react-native-reanimated/plugin`, which was renamed to `react-native-worklets/plugin`.".to_string(),
                    );
                }
                if let Some(worklets_idx) = plugins
                    .iter()
                    .rposition(|p| p == "react-native-worklets/plugin")
                    && worklets_idx + 1 != plugins.len()
                {
                    push_project_diagnostic(
                        out,
                        babel_path.clone(),
                        RuleId::RnReanimatedWorkletsPluginLast,
                        sev,
                        "rnReanimatedWorkletsPluginLast",
                        "react-native-worklets/plugin",
                        "`react-native-worklets/plugin` is not last in the Babel `plugins` array."
                            .to_string(),
                    );
                }
            }
        }
        break;
    }

    // 3. `rn-android-release-shrinking-disabled`
    for gradle_rel in ["android/app/build.gradle", "android/app/build.gradle.kts"] {
        let Some((gradle_path, gradle_src)) =
            find_manifest_in_pkg(graph, &pkg.root_dir, gradle_rel)
        else {
            continue;
        };
        let (disabled_minify, disabled_shrink) = check_gradle_release_shrinking(gradle_src);
        if (disabled_minify || disabled_shrink)
            && let Some(sev) = is_rule_enabled(RuleId::RnAndroidReleaseShrinkingDisabled)
        {
            let mut features = Vec::new();
            if disabled_minify {
                features.push("code minification");
            }
            if disabled_shrink {
                features.push("resource shrinking");
            }
            push_project_diagnostic(
                out,
                gradle_path,
                RuleId::RnAndroidReleaseShrinkingDisabled,
                sev,
                "rnAndroidReleaseShrinkingDisabled",
                "release",
                format!(
                    "The Android release build explicitly disables {}, leaving unreachable code or resources in the shipped app.",
                    features.join(" and ")
                ),
            );
            break;
        }
    }
}

fn check_expo_package_configs<F>(
    graph: &ProjectGraph,
    pkg: &WorkspacePackage,
    is_rule_enabled: &F,
    out: &mut Vec<Diagnostic>,
) where
    F: Fn(RuleId) -> Option<RuleSeverity>,
{
    let pkg_json_entry = find_manifest_in_pkg(graph, &pkg.root_dir, "package.json");
    let pkg_json_val: Option<Value> = pkg_json_entry
        .as_ref()
        .and_then(|(_, txt)| serde_json::from_str::<Value>(&strip_jsonc(txt)).ok());
    let pkg_json_path = pkg_json_entry
        .map(|(p, _)| p)
        .unwrap_or_else(|| pkg.root_dir.join("package.json"));

    let deps = &pkg.capability_gate.dependencies;
    let expo_sdk_major = deps.get("expo").and_then(|v| parse_major_version(v));

    // 1. `expo-no-unimodules-packages`
    if let Some(sev) = is_rule_enabled(RuleId::ExpoNoUnimodulesPackages) {
        for unimod in [
            "@unimodules/core",
            "@unimodules/react-native-adapter",
            "react-native-unimodules",
        ] {
            if deps.contains_key(unimod) {
                push_project_diagnostic(
                    out,
                    pkg_json_path.clone(),
                    RuleId::ExpoNoUnimodulesPackages,
                    sev,
                    "expoNoUnimodulesPackages",
                    unimod,
                    format!(
                        "\"{unimod}\" is a legacy unimodules package that is incompatible with Expo SDK 44+ and will break native builds."
                    ),
                );
            }
        }
    }

    // 2. `expo-no-cli-dependencies`
    if let Some(sev) = is_rule_enabled(RuleId::ExpoNoCliDependencies) {
        for cli_pkg in ["expo-cli", "eas-cli"] {
            if deps.contains_key(cli_pkg) {
                push_project_diagnostic(
                    out,
                    pkg_json_path.clone(),
                    RuleId::ExpoNoCliDependencies,
                    sev,
                    "expoNoCliDependencies",
                    cli_pkg,
                    format!("`{cli_pkg}` should not be installed as a project dependency."),
                );
            }
        }
    }

    // 3. `expo-no-redundant-dependency`
    if let Some(sev) = is_rule_enabled(RuleId::ExpoNoRedundantDependency) {
        let redundant_table: &[(&str, Option<u32>)] = &[
            ("expo-modules-autolinking", None),
            ("expo-dev-launcher", None),
            ("expo-dev-menu", None),
            ("expo-modules-core", None),
            ("@expo/metro-config", None),
            ("@types/react-native", Some(48)),
            ("@expo/config-plugins", Some(48)),
            ("@expo/prebuild-config", Some(53)),
            ("expo-permissions", Some(50)),
            ("expo-app-loading", Some(49)),
            ("expo-firebase-analytics", Some(48)),
            ("expo-firebase-recaptcha", Some(48)),
            ("expo-firebase-core", Some(48)),
        ];
        for &(pkg_name, min_sdk) in redundant_table {
            if !deps.contains_key(pkg_name) {
                continue;
            }
            if let Some(min) = min_sdk
                && expo_sdk_major.is_none_or(|sdk| sdk < min)
            {
                continue;
            }
            push_project_diagnostic(
                out,
                pkg_json_path.clone(),
                RuleId::ExpoNoRedundantDependency,
                sev,
                "expoNoRedundantDependency",
                pkg_name,
                format!("\"{pkg_name}\" should not be a direct dependency in this Expo project."),
            );
        }
    }

    // 4. `expo-no-conflicting-dependency-override`
    if let Some(sev) = is_rule_enabled(RuleId::ExpoNoConflictingDependencyOverride)
        && let Some(val) = &pkg_json_val
    {
        let mut overridden = Vec::new();
        for obj_opt in [
            val.get("overrides").and_then(Value::as_object),
            val.get("resolutions").and_then(Value::as_object),
            val.pointer("/pnpm/overrides").and_then(Value::as_object),
        ]
        .into_iter()
        .flatten()
        {
            for k in obj_opt.keys() {
                if matches!(
                    k.as_str(),
                    "@expo/cli"
                        | "@expo/config"
                        | "@expo/metro-config"
                        | "@expo/metro-runtime"
                        | "@expo/metro"
                        | "metro"
                ) || k.starts_with("metro-")
                {
                    overridden.push(format!("\"{k}\""));
                }
            }
        }
        overridden.sort();
        overridden.dedup();
        if !overridden.is_empty() {
            push_project_diagnostic(
                out,
                pkg_json_path.clone(),
                RuleId::ExpoNoConflictingDependencyOverride,
                sev,
                "expoNoConflictingDependencyOverride",
                "overrides",
                format!(
                    "package.json pins SDK-critical packages via overrides/resolutions ({}).",
                    overridden.join(", ")
                ),
            );
        }
    }

    // 5. `expo-router-no-react-navigation` (SDK 56)
    if expo_sdk_major == Some(56)
        && deps.contains_key("expo-router")
        && deps.keys().any(|k| k.starts_with("@react-navigation/"))
        && let Some(sev) = is_rule_enabled(RuleId::ExpoRouterNoReactNavigation)
    {
        push_project_diagnostic(
            out,
            pkg_json_path.clone(),
            RuleId::ExpoRouterNoReactNavigation,
            sev,
            "expoRouterNoReactNavigation",
            "expo-router",
            "As of SDK 56, expo-router is no longer compatible with directly installed @react-navigation packages.".to_string(),
        );
    }

    // 6. `expo-vector-icons-conflict` (SDK 56+)
    if expo_sdk_major.is_some_and(|sdk| sdk >= 56)
        && deps
            .keys()
            .any(|k| k.starts_with("@react-native-vector-icons/"))
        && (deps.contains_key("@expo/vector-icons")
            || deps.contains_key("react-native-vector-icons"))
        && let Some(sev) = is_rule_enabled(RuleId::ExpoVectorIconsConflict)
    {
        push_project_diagnostic(
            out,
            pkg_json_path.clone(),
            RuleId::ExpoVectorIconsConflict,
            sev,
            "expoVectorIconsConflict",
            "@expo/vector-icons",
            "This project installs both scoped `@react-native-vector-icons/*` packages and `@expo/vector-icons`.".to_string(),
        );
    }

    // 7. `expo-package-json-conflict`
    if let Some(sev) = is_rule_enabled(RuleId::ExpoPackageJsonConflict)
        && let Some(val) = &pkg_json_val
    {
        if let Some(scripts) = val.get("scripts").and_then(Value::as_object)
            && (scripts.contains_key("expo") || scripts.contains_key("react-native"))
        {
            push_project_diagnostic(
                out,
                pkg_json_path.clone(),
                RuleId::ExpoPackageJsonConflict,
                sev,
                "expoPackageJsonConflict",
                "scripts",
                "package.json defines a script named \"expo\" or \"react-native\" that shadows the CLI binary in node_modules/.bin.".to_string(),
            );
        }
        if let Some(pkg_name) = val.get("name").and_then(Value::as_str)
            && deps.contains_key(pkg_name)
        {
            push_project_diagnostic(
                out,
                pkg_json_path.clone(),
                RuleId::ExpoPackageJsonConflict,
                sev,
                "expoPackageJsonConflict",
                pkg_name,
                format!(
                    "package.json \"name\" is \"{pkg_name}\", which collides with a dependency of the same name."
                ),
            );
        }
    }

    // 8. `expo-lockfile`
    if let Some(sev) = is_rule_enabled(RuleId::ExpoLockfile) {
        let lockfile_names = [
            "pnpm-lock.yaml",
            "yarn.lock",
            "package-lock.json",
            "bun.lockb",
            "bun.lock",
        ];
        let present_lockfiles: Vec<&str> = lockfile_names
            .into_iter()
            .filter(|name| find_manifest_in_pkg(graph, &pkg.root_dir, name).is_some())
            .collect();
        if present_lockfiles.len() != 1 {
            let msg = if present_lockfiles.is_empty() {
                "No lock file detected at the project root — installs are not reproducible, and EAS Build cannot infer your package manager.".to_string()
            } else {
                format!(
                    "Multiple lock files detected ({}) — EAS Build infers the package manager from the lock file, so this is ambiguous.",
                    present_lockfiles.join(", ")
                )
            };
            push_project_diagnostic(
                out,
                pkg_json_path.clone(),
                RuleId::ExpoLockfile,
                sev,
                "expoLockfile",
                "lockfile",
                msg,
            );
        }
    }

    // 9. `expo-metro-config`
    if let Some(sev) = is_rule_enabled(RuleId::ExpoMetroConfig) {
        for metro_name in [
            "metro.config.js",
            "metro.config.cjs",
            "metro.config.mjs",
            "metro.config.ts",
        ] {
            if let Some((metro_path, metro_src)) =
                find_manifest_in_pkg(graph, &pkg.root_dir, metro_name)
            {
                let has_expo_signal = [
                    "expo/metro-config",
                    "@sentry/react-native/metro",
                    "getSentryExpoConfig",
                    "posthog-react-native/metro",
                    "getPostHogExpoConfig",
                ]
                .iter()
                .any(|sig| metro_src.contains(sig));
                if !has_expo_signal {
                    push_project_diagnostic(
                        out,
                        metro_path,
                        RuleId::ExpoMetroConfig,
                        sev,
                        "expoMetroConfig",
                        metro_name,
                        "Your metro.config does not extend `expo/metro-config`.".to_string(),
                    );
                }
                break;
            }
        }
    }

    // 10. `app.json` / `app.config.json` checks (`expo-reanimated-v4-requires-new-arch`, `expo-updates-no-unsafe-production-config`)
    let has_dynamic_app_config = [
        "app.config.ts",
        "app.config.js",
        "app.config.cjs",
        "app.config.mjs",
    ]
    .iter()
    .any(|n| find_manifest_in_pkg(graph, &pkg.root_dir, n).is_some());

    if !has_dynamic_app_config {
        for app_cfg_name in ["app.config.json", "app.json"] {
            let Some((app_path, app_src)) =
                find_manifest_in_pkg(graph, &pkg.root_dir, app_cfg_name)
            else {
                continue;
            };
            let Ok(app_val) = serde_json::from_str::<Value>(&strip_jsonc(app_src)) else {
                continue;
            };
            let Some(expo_obj) = app_val.get("expo").and_then(Value::as_object) else {
                continue;
            };

            let is_reanimated_v4 = deps
                .get("react-native-reanimated")
                .and_then(|v| parse_major_version(v))
                .is_some_and(|m| m >= 4)
                || deps.contains_key("react-native-worklets");

            if is_reanimated_v4
                && expo_obj.get("newArchEnabled").and_then(Value::as_bool) == Some(false)
                && let Some(sev) = is_rule_enabled(RuleId::ExpoReanimatedV4RequiresNewArch)
            {
                push_project_diagnostic(
                    out,
                    app_path.clone(),
                    RuleId::ExpoReanimatedV4RequiresNewArch,
                    sev,
                    "expoReanimatedV4RequiresNewArch",
                    "newArchEnabled",
                    "react-native-reanimated v4 supports only the New Architecture, but `newArchEnabled: false` is set in your app config.".to_string(),
                );
            }

            if expo_obj
                .get("updates")
                .and_then(Value::as_object)
                .and_then(|u| u.get("disableAntiBrickingMeasures"))
                .and_then(Value::as_bool)
                == Some(true)
                && let Some(sev) = is_rule_enabled(RuleId::ExpoUpdatesNoUnsafeProductionConfig)
            {
                push_project_diagnostic(
                    out,
                    app_path,
                    RuleId::ExpoUpdatesNoUnsafeProductionConfig,
                    sev,
                    "expoUpdatesNoUnsafeProductionConfig",
                    "disableAntiBrickingMeasures",
                    "`updates.disableAntiBrickingMeasures: true` disables expo-updates' recovery safeguards and can permanently brick installed apps.".to_string(),
                );
            }
            break;
        }
    }

    // 11. `expo-env-local-not-gitignored` & `expo-gitignore`
    let gitignore_src = find_manifest_in_pkg(graph, &pkg.root_dir, ".gitignore")
        .map(|(_, s)| s)
        .unwrap_or("");
    if let Some(sev) = is_rule_enabled(RuleId::ExpoEnvLocalNotGitignored) {
        let has_env_local = [
            ".env.local",
            ".env.development.local",
            ".env.production.local",
            ".env.test.local",
        ]
        .iter()
        .any(|n| find_manifest_in_pkg(graph, &pkg.root_dir, n).is_some());
        if has_env_local
            && !gitignore_src.contains(".env*.local")
            && !gitignore_src.contains(".env.local")
        {
            push_project_diagnostic(
                out,
                pkg_json_path.clone(),
                RuleId::ExpoEnvLocalNotGitignored,
                sev,
                "expoEnvLocalNotGitignored",
                ".env.local",
                "Local environment file (.env*.local) is not ignored by Git.".to_string(),
            );
        }
    }

    if let Some(sev) = is_rule_enabled(RuleId::ExpoGitignore)
        && !gitignore_src.is_empty()
    {
        let ignores_expo_dir = gitignore_src
            .lines()
            .any(|l| matches!(l.trim(), ".expo" | ".expo/" | "/.expo" | "/.expo/"));
        let unanchored_native_dirs = gitignore_src
            .lines()
            .any(|l| matches!(l.trim(), "android" | "ios" | "android/" | "ios/"))
            && graph.manifests.keys().any(|p| {
                let s = p.to_string_lossy();
                s.contains("modules/") && (s.contains("/android/") || s.contains("/ios/"))
            });
        if !ignores_expo_dir || unanchored_native_dirs {
            let msg = if unanchored_native_dirs {
                "The native `ios`/`android` directories of a local Expo module under `modules/` are gitignored; anchor `/ios` and `/android` in .gitignore.".to_string()
            } else {
                "`.expo/` state directory is not ignored in `.gitignore`; add `.expo/` to `.gitignore`.".to_string()
            };
            push_project_diagnostic(
                out,
                pkg.root_dir.join(".gitignore"),
                RuleId::ExpoGitignore,
                sev,
                "expoGitignore",
                ".gitignore",
                msg,
            );
        }
    }
}

fn push_project_diagnostic(
    out: &mut Vec<Diagnostic>,
    file: PathBuf,
    rule: RuleId,
    severity: RuleSeverity,
    message_id: &'static str,
    target_name: &str,
    message: String,
) {
    let meta = rule.metadata();
    out.push(Diagnostic {
        file,
        subject_name: None,
        rule,
        category: meta.category,
        severity,
        message_id,
        tier: meta.default_tier,
        target_name: target_name.to_string(),
        message,
        docs_url: meta.docs_url,
        loc: SourceLoc { line: 1, column: 1 },
        span: ByteSpan { start: 0, end: 0 },
        cascade_steps: Vec::new(),
        caller_sites: Vec::new(),
        autofix: None,
    });
}

fn parse_major_version(spec: &str) -> Option<u32> {
    let trimmed = spec.trim_start_matches(['^', '~', '=', '>', '<', ' ', 'v']);
    let major_str = trimmed.split('.').next()?;
    major_str.parse::<u32>().ok()
}

fn parse_rn_minor_version(spec: &str) -> Option<u32> {
    let trimmed = spec.trim_start_matches(['^', '~', '=', '>', '<', ' ', 'v']);
    let mut parts = trimmed.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    if major != 0 {
        return Some(100);
    }
    let minor = parts.next()?.parse::<u32>().ok()?;
    Some(minor)
}

fn has_enable_babel_runtime_version(babel_src: &str) -> bool {
    for line in babel_src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(idx) = trimmed.find("enableBabelRuntime") {
            let after = &trimmed[idx + "enableBabelRuntime".len()..];
            let after_colon = after.trim_start_matches(['"', '\'', ' ', ':']);
            if after_colon.starts_with('\'') || after_colon.starts_with('"') {
                return true;
            }
        }
    }
    false
}

fn extract_static_babel_plugins(babel_src: &str) -> Option<Vec<String>> {
    let plugins_idx = babel_src.find("plugins")?;
    let after = &babel_src[plugins_idx..];
    let open_bracket = after.find('[')?;
    let inside = &after[open_bracket + 1..];
    if inside.contains("...") {
        return None;
    }
    let mut out = Vec::new();
    let mut depth = 1_i32;
    let mut bytes = inside.as_bytes().iter().copied().enumerate();
    let mut item_has_pushed = false;

    while let Some((idx, b)) = bytes.next() {
        match b {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            b',' if depth == 1 => {
                item_has_pushed = false;
            }
            b'\'' | b'"' if !item_has_pushed => {
                let quote = b;
                let start = idx + 1;
                let mut end = start;
                for (next_idx, next_b) in bytes.by_ref() {
                    if next_b == quote {
                        end = next_idx;
                        break;
                    }
                }
                if end > start
                    && let Some(s) = inside.get(start..end)
                {
                    out.push(s.to_string());
                    item_has_pushed = true;
                }
            }
            _ => {}
        }
    }
    Some(out)
}

fn check_gradle_release_shrinking(gradle_src: &str) -> (bool, bool) {
    let mut in_release = false;
    let mut minify: Option<bool> = None;
    let mut shrink: Option<bool> = None;

    for raw_line in gradle_src.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.contains("println(") {
            continue;
        }
        if line.starts_with("release")
            || line.contains("release {")
            || line.contains("getByName(\"release\")")
            || line.contains("named(\"release\")")
        {
            in_release = true;
        }
        if in_release {
            if line.contains("minifyEnabled") || line.contains("isMinifyEnabled") {
                if line.ends_with("false") {
                    minify = Some(false);
                } else if line.ends_with("true") {
                    minify = Some(true);
                } else {
                    minify = None;
                }
            }
            if line.contains("shrinkResources") || line.contains("isShrinkResources") {
                if line.ends_with("false") {
                    shrink = Some(false);
                } else if line.ends_with("true") {
                    shrink = Some(true);
                } else {
                    shrink = None;
                }
            }
        }
    }

    (minify == Some(false), shrink == Some(false))
}
