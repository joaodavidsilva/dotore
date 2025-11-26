//! Integration tests for Ticket #03: Native Fuzzy Symbol Outline Search (`dotore search`).

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use dotore::{
    SearchJsonReport, SearchOptions, SymbolKind, format_search_json, format_search_text,
    parse_file_ir, score_fuzzy, search_project_sources, search_symbols, should_highlight_search,
};

#[test]
fn oxc_extracts_all_twelve_symbol_kinds_with_signatures_comments_and_containers() {
    let source = r##"import DefaultWidget, { useTheme, type ThemeConfig } from "./theme";
import * as Icons from "./icons";

/**
 * Primary UI button component.
 * Supports primary and secondary variants.
 */
export function Button(
    props: ButtonProps,
): JSX.Element {
    function computeLabel() {
        return props.label;
    }
    return <button>{computeLabel()}</button>;
}

// Public props for Button.
export interface ButtonProps {
    label: string;
    onClick(): void;
}

export type ButtonVariant = "primary" | "secondary";

export enum ButtonSize {
    Small = "sm",
    Large = "lg",
}

export const DEFAULT_SIZE = ButtonSize.Small;
let renderCounter = 0;
const { primaryColor, secondaryColor: secColor } = { primaryColor: "#000", secondaryColor: "#fff" };

export class ButtonController {
    readonly #secret = 42;
    accessor active: boolean = false;
    /** Handles click interactions. */
    handleClick(): void {}
}

const buttonHelpers = {
    // Default size when no explicit prop is provided.
    defaultSize: ButtonSize.Small,
    formatLabel(raw: string) {
        return raw.trim();
    },
};

/* Inline doc */ export const ArrowWidget = (x: number) => {
    return x + 1;
};

export { renderCounter as exportedCounter };
export * as IconSet from "./icons";
export default Button;
"##;

    let ir = parse_file_ir(Path::new("src/button.tsx"), source);
    let outlines = &ir.symbol_outlines;

    // 1. Imports (`ImportDefaultSpecifier`, `ImportSpecifier`, `ImportNamespaceSpecifier`)
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "DefaultWidget" && s.kind == SymbolKind::Import)
    );
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "useTheme" && s.kind == SymbolKind::Import)
    );
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "ThemeConfig" && s.kind == SymbolKind::Import)
    );
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "Icons" && s.kind == SymbolKind::Import)
    );

    // 2. Function (multi-line signature, leading block doc comment, nested function with container)
    let button_fn = outlines
        .iter()
        .find(|s| s.name == "Button" && s.kind == SymbolKind::Function)
        .expect("Button function outline");
    assert!(button_fn.exported);
    assert_eq!(button_fn.comment_start_line, Some(4));
    assert_eq!(button_fn.loc.line, 8);
    assert_eq!(button_fn.signature_end_line, 10);
    assert_eq!(button_fn.end_line, 15);
    assert_eq!(
        button_fn.signature,
        "export function Button( props: ButtonProps, ): JSX.Element"
    );
    assert!(
        button_fn
            .doc_comment
            .as_deref()
            .is_some_and(|c| c.contains("Primary UI button component."))
    );

    let nested_fn = outlines
        .iter()
        .find(|s| s.name == "computeLabel" && s.kind == SymbolKind::Function)
        .expect("nested computeLabel function outline");
    assert_eq!(nested_fn.parent_name.as_deref(), Some("Button"));

    // 3. Interface + interface property & method signatures
    let iface = outlines
        .iter()
        .find(|s| s.name == "ButtonProps" && s.kind == SymbolKind::Interface)
        .expect("ButtonProps interface");
    assert_eq!(iface.comment_start_line, Some(17));
    assert!(
        iface
            .doc_comment
            .as_deref()
            .is_some_and(|c| c.contains("Public props for Button."))
    );
    assert!(outlines.iter().any(|s| s.name == "label"
        && s.kind == SymbolKind::Property
        && s.parent_name.as_deref() == Some("ButtonProps")));
    assert!(outlines.iter().any(|s| s.name == "onClick"
        && s.kind == SymbolKind::Method
        && s.parent_name.as_deref() == Some("ButtonProps")));

    // 4. Type alias
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "ButtonVariant" && s.kind == SymbolKind::Type)
    );

    // 5. Enum + EnumMember
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "ButtonSize" && s.kind == SymbolKind::Enum)
    );
    assert!(outlines.iter().any(|s| s.name == "Small"
        && s.kind == SymbolKind::EnumMember
        && s.parent_name.as_deref() == Some("ButtonSize")));
    assert!(outlines.iter().any(|s| s.name == "Large"
        && s.kind == SymbolKind::EnumMember
        && s.parent_name.as_deref() == Some("ButtonSize")));

    // 6. Constant & Variable (including destructured object bindings)
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "DEFAULT_SIZE" && s.kind == SymbolKind::Constant)
    );
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "renderCounter" && s.kind == SymbolKind::Variable)
    );
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "primaryColor" && s.kind == SymbolKind::Constant)
    );
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "secColor" && s.kind == SymbolKind::Constant)
    );

    // 7. Class + PrivateIdentifier property + AccessorProperty + Method
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "ButtonController" && s.kind == SymbolKind::Class)
    );
    assert!(outlines.iter().any(|s| s.name == "#secret"
        && s.kind == SymbolKind::Property
        && s.parent_name.as_deref() == Some("ButtonController")));
    assert!(outlines.iter().any(|s| s.name == "active"
        && s.kind == SymbolKind::Property
        && s.parent_name.as_deref() == Some("ButtonController")));
    let click_method = outlines
        .iter()
        .find(|s| s.name == "handleClick" && s.kind == SymbolKind::Method)
        .expect("handleClick method");
    assert_eq!(
        click_method.parent_name.as_deref(),
        Some("ButtonController")
    );
    assert!(
        click_method
            .doc_comment
            .as_deref()
            .is_some_and(|c| c.contains("Handles click interactions."))
    );

    // 8. Object literal property and method with enclosing container
    let obj_prop = outlines
        .iter()
        .find(|s| s.name == "defaultSize" && s.kind == SymbolKind::Property)
        .expect("object property defaultSize");
    assert_eq!(obj_prop.parent_name.as_deref(), Some("buttonHelpers"));
    assert!(
        obj_prop
            .doc_comment
            .as_deref()
            .is_some_and(|c| c.contains("Default size when no explicit prop"))
    );
    let obj_method = outlines
        .iter()
        .find(|s| s.name == "formatLabel" && s.kind == SymbolKind::Method)
        .expect("object method formatLabel");
    assert_eq!(obj_method.parent_name.as_deref(), Some("buttonHelpers"));

    // 9. Arrow function with inline leading block comment
    let arrow_fn = outlines
        .iter()
        .find(|s| s.name == "ArrowWidget" && s.kind == SymbolKind::Function)
        .expect("ArrowWidget function");
    assert!(
        arrow_fn
            .doc_comment
            .as_deref()
            .is_some_and(|c| c.contains("Inline doc"))
    );

    // 10. Exports (`ExportSpecifier`, `ExportAllDeclaration` named, `ExportDefaultDeclaration`)
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "exportedCounter" && s.kind == SymbolKind::Export)
    );
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "IconSet" && s.kind == SymbolKind::Export)
    );
    assert!(
        outlines
            .iter()
            .any(|s| s.name == "default" && s.kind == SymbolKind::Export)
    );
}

#[test]
fn fuzzy_matching_and_ranking_rewards_prefix_camel_case_kebab_boundary_and_contiguity() {
    // Empty query or empty candidate returns None
    assert!(score_fuzzy("", "Button").is_none());
    assert!(score_fuzzy("   ", "Button").is_none());
    assert!(score_fuzzy("btn", "").is_none());
    assert!(score_fuzzy("xyz", "Button").is_none());

    // Exact prefix match outscores mid-word match
    let (prefix_score, prefix_matches) = score_fuzzy("Button", "Button").unwrap();
    let (longer_score, _) = score_fuzzy("Button", "ButtonGroup").unwrap();
    let (mid_score, _) = score_fuzzy("Button", "PrimaryButton").unwrap();
    assert_eq!(prefix_matches, vec![0, 1, 2, 3, 4, 5]);
    assert!(prefix_score > longer_score);
    assert!(longer_score > mid_score);

    // camelCase boundary match ("ubp" -> `useButtonPress`) outscores non-boundary subsequence (`unbalanced_p`)
    let (camel_score, camel_matches) = score_fuzzy("ubp", "useButtonPress").unwrap();
    let (non_boundary_score, _) = score_fuzzy("ubp", "suboptimal").unwrap();
    assert_eq!(camel_matches, vec![0, 3, 9]);
    assert!(camel_score > non_boundary_score);

    // kebab-case / snake_case boundary match ("fb" -> `format-badge` / `format_badge`)
    let (kebab_score, kebab_matches) = score_fuzzy("fb", "format-badge").unwrap();
    let (flat_score, _) = score_fuzzy("fb", "fabrics").unwrap();
    assert_eq!(kebab_matches, vec![0, 7]);
    assert!(kebab_score > flat_score);

    // Ranking across multiple in-memory files
    let files = vec![
        (
            PathBuf::from("src/secondary.tsx"),
            "export function PrimaryButton() {}\nexport function useButtonState() {}\n".to_string(),
        ),
        (
            PathBuf::from("src/button.tsx"),
            "export function Button() {}\nexport function ButtonGroup() {}\n".to_string(),
        ),
    ];
    let ranked = search_project_sources("Button", &files, None, 50);
    let ranked_names: Vec<&str> = ranked.iter().map(|r| r.outline.name.as_str()).collect();
    assert_eq!(
        ranked_names,
        vec!["Button", "ButtonGroup", "useButtonState", "PrimaryButton"]
    );
}

#[test]
fn kind_filter_defaults_to_seven_kinds_and_limit_caps_results() {
    let source = r#"import { targetImport } from "./dep";
export const TARGET_CONST = 1;
export let targetVar = 2;
export enum TargetEnum {
    targetMember = "m",
}
export interface TargetInterface {
    targetProp: string;
    targetMethod(): void;
}
export type TargetType = string;
export class TargetClass {}
export function targetFunction() {}
export { targetVar as targetExport };
"#;
    let files = vec![(PathBuf::from("src/targets.ts"), source.to_string())];

    // Default kinds: class, enum, function, interface, method, property, type (7 kinds)
    let default_hits = search_project_sources("target", &files, None, 50);
    let default_kinds: Vec<SymbolKind> = default_hits.iter().map(|r| r.outline.kind).collect();
    assert!(default_kinds.contains(&SymbolKind::Class));
    assert!(default_kinds.contains(&SymbolKind::Enum));
    assert!(default_kinds.contains(&SymbolKind::Function));
    assert!(default_kinds.contains(&SymbolKind::Interface));
    assert!(default_kinds.contains(&SymbolKind::Method));
    assert!(default_kinds.contains(&SymbolKind::Property));
    assert!(default_kinds.contains(&SymbolKind::Type));
    // Excluded by default:
    assert!(!default_kinds.contains(&SymbolKind::Constant));
    assert!(!default_kinds.contains(&SymbolKind::Variable));
    assert!(!default_kinds.contains(&SymbolKind::EnumMember));
    assert!(!default_kinds.contains(&SymbolKind::Import));
    assert!(!default_kinds.contains(&SymbolKind::Export));

    // Explicit `--kind constant,enum-member,import,export,variable`
    let extra_kinds = [
        SymbolKind::Constant,
        SymbolKind::EnumMember,
        SymbolKind::Import,
        SymbolKind::Export,
        SymbolKind::Variable,
    ];
    let extra_hits = search_project_sources("target", &files, Some(&extra_kinds), 50);
    let extra_names: Vec<&str> = extra_hits.iter().map(|r| r.outline.name.as_str()).collect();
    assert_eq!(extra_names.len(), 5);
    assert!(extra_names.contains(&"TARGET_CONST"));
    assert!(extra_names.contains(&"targetMember"));
    assert!(extra_names.contains(&"targetImport"));
    assert!(extra_names.contains(&"targetExport"));
    assert!(extra_names.contains(&"targetVar"));

    // Limit caps results
    let limited = search_project_sources("target", &files, None, 3);
    assert_eq!(limited.len(), 3);
}

#[test]
fn text_format_renders_grouped_outlines_truncates_long_comments_wraps_members_and_summarizes_large_interfaces()
 {
    let source = r#"/**
 * Comment line 1
 * Comment line 2
 * Comment line 3
 * Comment line 4
 * Comment line 5
 * Comment line 6
 * Comment line 7
 * Comment line 8
 * Comment line 9
 * Comment line 10
 * Comment line 11
 */
export function MatchVerboseButton(props: MegaMatchProps) {
    const x = 1;
    return x;
}

export class MatchController {
    private count = 0;

    /** Handles match click. */
    handleMatchClick(): void {
        this.count += 1;
    }

    trailingHelper(): void {}
}

const matchObject = {
    firstKey: 1,
    // Object property comment.
    matchPropValue: 42,
    lastKey: 2,
};

export interface MegaMatchProps {
    prop01: string;
    prop02: string;
    prop03: string;
    prop04: string;
    prop05: string;
    prop06: string;
    prop07: string;
    prop08: string;
    prop09: string;
    prop10: string;
    prop11: string;
    prop12: string;
    prop13: string;
    prop14: string;
    prop15: string;
    prop16: string;
    prop17: string;
    prop18: string;
}
"#;

    let file_path = PathBuf::from("src/match_view.tsx");
    let files = vec![(file_path.clone(), source.to_string())];
    let results = search_project_sources("Match", &files, None, 50);
    let mut sources = HashMap::new();
    sources.insert(file_path, source.to_string());

    let text = format_search_text(&results, &sources, false);

    // 1. File header and code fence
    assert!(text.starts_with("src/match_view.tsx\n```tsx\n"));
    assert!(text.trim_end().ends_with("```"));

    // 2. Comment longer than 10 lines is truncated with synthetic summary line
    assert!(text.contains("  10 |  * Comment line 9"));
    assert!(!text.contains("Comment line 10"));
    assert!(text.contains("     |  (...and 3 more comment lines)"));
    assert!(text.contains("  14 | export function MatchVerboseButton(props: MegaMatchProps) {"));
    assert!(text.contains("  15 |   ..."));
    assert!(text.contains("  17 | }"));

    // 3. Method match includes enclosing class header and `...` ellipses
    assert!(text.contains("  19 | export class MatchController {\n     |   ...\n  22 |     /** Handles match click. */\n  23 |     handleMatchClick(): void {\n  24 |       ...\n  25 |     }\n     |   ...\n  28 | }"));

    // 4. Object property match includes enclosing object header and `...` ellipses
    assert!(text.contains("  30 | const matchObject = {\n     |   ...\n  32 |     // Object property comment.\n  33 |     matchPropValue: 42,\n     |   ...\n  35 | };"));

    // 5. Interface with > 15 properties shows first 15 and summarizes remaining 3
    assert!(text.contains("  37 | export interface MegaMatchProps {"));
    assert!(text.contains("  52 |     prop15: string;"));
    assert!(!text.contains("prop16: string;"));
    assert!(text.contains("     |     (...and 3 more properties)\n  56 | }"));
}

#[test]
fn json_format_and_cli_subcommand_respect_color_and_terminal_rules() {
    // 1. Color gate unit checks
    assert!(!should_highlight_search(false, false, &[]));
    assert!(should_highlight_search(false, true, &[]));
    assert!(!should_highlight_search(true, true, &[]));
    assert!(!should_highlight_search(
        false,
        true,
        &[("NO_COLOR".to_string(), "1".to_string())]
    ));
    assert!(!should_highlight_search(
        false,
        true,
        &[("CI".to_string(), "true".to_string())]
    ));
    assert!(!should_highlight_search(
        false,
        true,
        &[("TERM".to_string(), "dumb".to_string())]
    ));
    assert!(should_highlight_search(
        false,
        false,
        &[("FORCE_COLOR".to_string(), "1".to_string())]
    ));

    // 2. End-to-end CLI test on a temporary workspace
    let temp_dir = std::env::temp_dir().join(format!("dotore-search-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    let src_dir = temp_dir.join("src");
    fs::create_dir_all(&src_dir).expect("create temp src dir");

    let file_content = r#"/** Renders the primary button action. */
export function Button(props: ButtonProps) {
    return null;
}

export interface ButtonProps {
    label: string;
}

export const BUTTON_DEFAULT_LABEL = "Click";
"#;
    fs::write(src_dir.join("button.tsx"), file_content).expect("write button.tsx");

    let bin = env!("CARGO_BIN_EXE_dotore");

    // CLI JSON output
    let json_out = Command::new(bin)
        .current_dir(&temp_dir)
        .args([
            "search",
            "btn",
            "src",
            "--kind",
            "function,constant",
            "--limit",
            "1",
            "--format",
            "json",
        ])
        .output()
        .expect("run dotore search --format json");
    assert!(json_out.status.success());
    let report: SearchJsonReport =
        serde_json::from_slice(&json_out.stdout).expect("parse SearchJsonReport");
    assert_eq!(report.query, "btn");
    assert_eq!(report.root, "src");
    assert_eq!(report.count, 1);
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].name, "Button");
    assert_eq!(report.results[0].kind, SymbolKind::Function);
    assert_eq!(report.results[0].location.file, "src/button.tsx");
    assert_eq!(report.results[0].location.line, 2);
    assert_eq!(report.results[0].location.column, 17);
    assert_eq!(
        report.results[0].signature,
        "export function Button(props: ButtonProps)"
    );
    assert_eq!(
        report.results[0].comments.as_deref(),
        Some(&["/** Renders the primary button action. */".to_string()][..])
    );
    assert_eq!(report.results[0].matches, vec![0, 2, 5]);

    // CLI Text output with `--no-color` has no ANSI codes
    let text_out = Command::new(bin)
        .current_dir(&temp_dir)
        .args(["search", "Button", "src", "--no-color"])
        .output()
        .expect("run dotore search --no-color");
    assert!(text_out.status.success());
    let stdout_str = String::from_utf8_lossy(&text_out.stdout);
    assert!(!stdout_str.contains("\x1b["));
    assert!(stdout_str.contains("src/button.tsx\n```tsx\n"));
    assert!(stdout_str.contains("   1 | /** Renders the primary button action. */\n   2 | export function Button(props: ButtonProps) {\n   3 |   ...\n   4 | }"));

    // Library `search_symbols` and `format_search_json` round-trip
    let (lib_results, _) = search_symbols(
        "Button",
        &SearchOptions {
            paths: vec![src_dir.clone()],
            kinds: Some(vec![SymbolKind::Function]),
            limit: 10,
            include_tests: true,
        },
    )
    .expect("search_symbols");
    assert_eq!(lib_results.len(), 1);
    let lib_json = format_search_json("Button", "src", &lib_results);
    assert_eq!(lib_json.count, 1);

    // Invalid `--kind` exits with code 2
    let bad_kind = Command::new(bin)
        .current_dir(&temp_dir)
        .args(["search", "Button", "--kind", "not-a-kind"])
        .output()
        .expect("run dotore search with invalid kind");
    assert_eq!(bad_kind.status.code(), Some(2));

    let _ = fs::remove_dir_all(&temp_dir);
}
