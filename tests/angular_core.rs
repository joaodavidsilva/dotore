//! Integration tests for Ticket #52: Angular Signals, lifecycle, decorator, and DI rules (`#50`).

use std::path::PathBuf;

use std::path::Path;

use dotore::{
    Capability, CapabilityGate, CliOverrides, DotoreConfig, PackageRole, PrescriptionTier, RuleId,
    ScanOptions, analyze_project_sources, analyze_source, analyze_source_with_config,
    apply_patches_to_source, discover_workspace_packages, filter_workspace_packages,
    scan_workspace_with_overrides,
};

#[test]
fn angular_json_multi_project_workspace_discovery_on_disk_and_virtual() {
    let angular_json = r#"{
  "$schema": "./node_modules/@angular/cli/lib/config/schema.json",
  "version": 1,
  "projects": {
    "portal-app": {
      "projectType": "application",
      "root": "projects/portal-app",
      "sourceRoot": "projects/portal-app/src",
      "architect": {
        "build": {
          "options": {
            "browser": "projects/portal-app/src/main.ts"
          }
        }
      }
    },
    "ui-kit": {
      "projectType": "library",
      "root": "projects/ui-kit",
      "sourceRoot": "projects/ui-kit/src"
    }
  }
}"#;
    let root_pkg_json = r#"{
  "name": "acme-ng-workspace",
  "private": true,
  "dependencies": {
    "@angular/core": "^19.0.0",
    "rxjs": "^7.8.0"
  }
}"#;
    let portal_comp = r#"
import { Component, signal, effect } from '@angular/core';

@Component({
  selector: 'app-portal',
  template: `<p>{{ count() }}</p>`,
})
export class PortalComponent {
  count = signal(0);
  doubled = signal(0);
  constructor() {
    effect(() => {
      this.doubled.set(this.count() * 2);
    });
  }
}
"#;
    let ui_kit_comp = r#"
import { Component, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'ui-button',
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<button><ng-content /></button>`,
})
export class UiButtonComponent {}
"#;

    // 1. Virtual `analyze_project_sources`
    let virtual_report = analyze_project_sources(
        vec![
            (PathBuf::from("package.json"), root_pkg_json.to_string()),
            (PathBuf::from("angular.json"), angular_json.to_string()),
            (
                PathBuf::from("projects/portal-app/src/portal.component.ts"),
                portal_comp.to_string(),
            ),
            (
                PathBuf::from("projects/ui-kit/src/ui-button.component.ts"),
                ui_kit_comp.to_string(),
            ),
        ],
        None,
    );

    let portal_proj = virtual_report
        .projects
        .iter()
        .find(|p| p.name == "portal-app")
        .unwrap_or_else(|| {
            panic!(
                "Expected portal-app in virtual report.projects, got: {:#?}",
                virtual_report.projects
            )
        });
    assert_eq!(portal_proj.role, PackageRole::Application);
    assert!(portal_proj.capabilities.contains(&Capability::Angular));

    let ui_kit_proj = virtual_report
        .projects
        .iter()
        .find(|p| p.name == "ui-kit")
        .unwrap_or_else(|| {
            panic!(
                "Expected ui-kit in virtual report.projects, got: {:#?}",
                virtual_report.projects
            )
        });
    assert_eq!(ui_kit_proj.role, PackageRole::Library);
    assert!(ui_kit_proj.capabilities.contains(&Capability::Angular));

    // 2. On-disk `discover_workspace_packages`, `filter_workspace_packages`, and `--project`
    let tmp = std::env::temp_dir().join(format!(
        "dotore-ng-multiproj-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let app_src_dir = tmp.join("projects/portal-app/src");
    let lib_src_dir = tmp.join("projects/ui-kit/src");
    std::fs::create_dir_all(&app_src_dir).unwrap();
    std::fs::create_dir_all(&lib_src_dir).unwrap();
    std::fs::write(tmp.join("package.json"), root_pkg_json).unwrap();
    std::fs::write(tmp.join("angular.json"), angular_json).unwrap();
    std::fs::write(app_src_dir.join("portal.component.ts"), portal_comp).unwrap();
    std::fs::write(lib_src_dir.join("ui-button.component.ts"), ui_kit_comp).unwrap();

    let pkgs = discover_workspace_packages(&tmp);
    let disk_portal = pkgs
        .iter()
        .find(|p| p.name == "portal-app")
        .unwrap_or_else(|| panic!("Expected portal-app package on disk, got: {pkgs:#?}"));
    assert_eq!(disk_portal.root_dir, tmp.join("projects/portal-app"));
    assert_eq!(
        disk_portal.capability_gate.package_role,
        PackageRole::Application
    );
    assert!(disk_portal.capability_gate.has(Capability::Angular));
    assert!(disk_portal.capability_gate.has(Capability::Rxjs));
    assert!(disk_portal.capability_gate.has(Capability::TypeScript));

    let disk_lib = pkgs
        .iter()
        .find(|p| p.name == "ui-kit")
        .unwrap_or_else(|| panic!("Expected ui-kit package on disk, got: {pkgs:#?}"));
    assert_eq!(disk_lib.root_dir, tmp.join("projects/ui-kit"));
    assert_eq!(disk_lib.capability_gate.package_role, PackageRole::Library);
    assert!(disk_lib.capability_gate.has(Capability::Angular));

    // `--project ui-kit` filtering works even though `projects/ui-kit` has no `package.json`
    let filtered = filter_workspace_packages(&pkgs, &tmp, &["ui-kit".to_string()]).unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "ui-kit");

    let (lib_only_report, _) = scan_workspace_with_overrides(
        &ScanOptions {
            paths: vec![tmp.clone()],
            include_tests: false,
            rules: Some(vec![
                RuleId::AngularNoSignalWriteInEffect,
                RuleId::AngularPreferOnPushChangeDetection,
            ]),
            tiers: None,
        },
        &CliOverrides {
            projects: vec!["ui-kit".to_string()],
            ..Default::default()
        },
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&tmp);

    assert_eq!(lib_only_report.projects.len(), 1);
    assert_eq!(lib_only_report.projects[0].name, "ui-kit");
    assert_eq!(lib_only_report.projects[0].role, PackageRole::Library);
    assert!(
        lib_only_report.diagnostics.is_empty(),
        "Expected portal-app diagnostics to be excluded when --project ui-kit is set, got: {:#?}",
        lib_only_report.diagnostics
    );

}

#[test]
fn angular_signals_rules_uncalled_signals_signal_model_and_prefer_signals() {
    // 1. `angular-no-uncalled-signals`
    let invalid_uncalled = r#"
import { Component, ChangeDetectionStrategy, signal, computed, input } from '@angular/core';

@Component({
  selector: 'app-status',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<div>Status</div>`,
})
export class StatusComponent {
  count = signal(0);
  isReady = computed(() => this.count() > 0);
  label = input('default');

  check(): string {
    if (this.isReady) {
      return this.count > 5 ? this.label() : 'low';
    }
    if (!this.label) {
      return 'missing';
    }
    return 'idle';
  }
}
"#;
    let uncalled_diags = analyze_source(
        Path::new("src/status.component.ts"),
        invalid_uncalled,
        Some(&[RuleId::AngularNoUncalledSignals]),
    );
    assert_eq!(
        uncalled_diags.len(),
        3,
        "Expected 3 uncalled signal diagnostics (this.isReady, this.count > 5, !this.label), got: {uncalled_diags:#?}"
    );
    assert!(uncalled_diags.iter().all(|d| d.tier == PrescriptionTier::Autofix));
    let (fixed_uncalled, _) = apply_patches_to_source(invalid_uncalled, &uncalled_diags);
    let reanalyzed = analyze_source(
        Path::new("src/status.component.ts"),
        &fixed_uncalled,
        Some(&[RuleId::AngularNoUncalledSignals]),
    );
    assert!(
        reanalyzed.is_empty(),
        "Expected 0 diagnostics after angular-no-uncalled-signals autofix, got: {reanalyzed:#?}\nSource:\n{fixed_uncalled}"
    );

    // Valid: signals properly called with `()` or mutated via `.set()` / `.update()`
    let valid_signals = r#"
import { Component, ChangeDetectionStrategy, signal, computed, input } from '@angular/core';

@Component({
  selector: 'app-status',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<div>Status</div>`,
})
export class StatusComponent {
  count = signal(0);
  isReady = computed(() => this.count() > 0);
  label = input('default');

  check(): string {
    this.count.set(1);
    this.count.update(v => v + 1);
    if (this.isReady()) {
      return this.count() > 5 ? this.label() : 'low';
    }
    return 'idle';
  }
}
"#;
    assert!(
        analyze_source(
            Path::new("src/status.component.ts"),
            valid_signals,
            Some(&[RuleId::AngularNoUncalledSignals]),
        )
        .is_empty()
    );

    // Arithmetic expressions like `this.count + 1` are type errors, not uncalled boolean/relational conditions
    let arithmetic_sig = r#"
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
@Component({
  selector: 'app-arith',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<div>Arith</div>`,
})
export class ArithComponent {
  count = signal(0);
  compute(): number {
    return (this.count as unknown as number) + 1;
  }
}
"#;
    assert!(
        analyze_source(
            Path::new("src/arith.component.ts"),
            arithmetic_sig,
            Some(&[RuleId::AngularNoUncalledSignals]),
        )
        .is_empty()
    );

    // 2. `angular-prefer-signal-model`
    let invalid_model = r#"
import { Component, ChangeDetectionStrategy, Input, Output, EventEmitter } from '@angular/core';

@Component({
  selector: 'app-slider',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<input />`,
})
export class SliderComponent {
  @Input() value = 0;
  @Output() readonly valueChange = new EventEmitter<number>();
}
"#;
    let model_diags = analyze_source(
        Path::new("src/slider.component.ts"),
        invalid_model,
        Some(&[RuleId::AngularPreferSignalModel]),
    );
    assert_eq!(model_diags.len(), 1);
    assert_eq!(model_diags[0].rule, RuleId::AngularPreferSignalModel);
    assert_eq!(model_diags[0].target_name, "value");

    let valid_model = r#"
import { Component, ChangeDetectionStrategy, model, output } from '@angular/core';

@Component({
  selector: 'app-slider',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<input />`,
})
export class SliderComponent {
  value = model(0);
  readonly committed = output<number>();
}
"#;
    assert!(
        analyze_source(
            Path::new("src/slider.component.ts"),
            valid_model,
            Some(&[RuleId::AngularPreferSignalModel, RuleId::AngularPreferSignals]),
        )
        .is_empty()
    );

    // 3. `angular-prefer-signals`
    let invalid_prefer_signals = r#"
import { Component, ChangeDetectionStrategy, Input } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Component({
  selector: 'app-counter-legacy',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<p>{{ title }}</p>`,
})
export class CounterLegacyComponent {
  @Input() title = '';
  count$ = new BehaviorSubject<number>(0);
}
"#;
    let prefer_sig_diags = analyze_source(
        Path::new("src/counter-legacy.component.ts"),
        invalid_prefer_signals,
        Some(&[RuleId::AngularPreferSignals]),
    );
    assert_eq!(prefer_sig_diags.len(), 2);
    assert!(
        prefer_sig_diags
            .iter()
            .all(|d| d.rule == RuleId::AngularPreferSignals)
    );
}

#[test]
fn angular_lifecycle_and_decorator_contract_rules_fire_and_respect_valid_cases() {
    // 4. `angular-no-conflicting-lifecycle`
    let conflicting = r#"
import { Component, ChangeDetectionStrategy, OnChanges, DoCheck } from '@angular/core';

@Component({
  selector: 'app-conflict',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<p>Conflict</p>`,
})
export class ConflictComponent implements OnChanges, DoCheck {
  ngOnChanges(): void { console.log('changes'); }
  ngDoCheck(): void { console.log('check'); }
}
"#;
    let conflict_diags = analyze_source(
        Path::new("src/conflict.component.ts"),
        conflicting,
        Some(&[RuleId::AngularNoConflictingLifecycle]),
    );
    assert_eq!(conflict_diags.len(), 1);
    assert_eq!(conflict_diags[0].rule, RuleId::AngularNoConflictingLifecycle);

    // 5. `angular-contextual-lifecycle` & 6. `angular-contextual-decorator`
    let bad_service = r#"
import { Injectable, Input, ViewChild, OnInit } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class DataService implements OnInit {
  @Input() endpoint = '/api';
  @ViewChild('ref') ref: unknown;

  ngOnInit(): void {
    console.log(this.endpoint);
  }
}
"#;
    let ctx_diags = analyze_source(
        Path::new("src/data.service.ts"),
        bad_service,
        Some(&[
            RuleId::AngularContextualLifecycle,
            RuleId::AngularContextualDecorator,
        ]),
    );
    assert!(
        ctx_diags
            .iter()
            .any(|d| d.rule == RuleId::AngularContextualLifecycle)
    );
    assert_eq!(
        ctx_diags
            .iter()
            .filter(|d| d.rule == RuleId::AngularContextualDecorator)
            .count(),
        2
    );

    // Valid: `ngOnDestroy` on `@Injectable` is allowed
    let valid_service = r#"
import { Injectable, OnDestroy } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class DataService implements OnDestroy {
  ngOnDestroy(): void {
    console.log('destroyed');
  }
}
"#;
    assert!(
        analyze_source(
            Path::new("src/data.service.ts"),
            valid_service,
            Some(&[
                RuleId::AngularContextualLifecycle,
                RuleId::AngularContextualDecorator,
            ]),
        )
        .is_empty()
    );

    // 7. `angular-no-async-lifecycle-method`, 8. `angular-no-lifecycle-call`,
    // 9. `angular-require-lifecycle-on-prototype`, 10. `angular-no-empty-lifecycle-method`,
    // 11. `angular-use-lifecycle-interface`
    let lifecycle_issues = r#"
import { Component, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'app-lifecycle',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<p>Lifecycle</p>`,
})
export class LifecycleComponent {
  async ngOnInit(): Promise<void> {
    await Promise.resolve();
  }

  ngOnDestroy = (): void => {
    console.log('destroy');
  };

  ngAfterViewInit(): void {}

  reload(): void {
    this.ngOnInit();
  }
}
"#;
    let lc_diags = analyze_source(
        Path::new("src/lifecycle.component.ts"),
        lifecycle_issues,
        Some(&[
            RuleId::AngularNoAsyncLifecycleMethod,
            RuleId::AngularNoLifecycleCall,
            RuleId::AngularRequireLifecycleOnPrototype,
            RuleId::AngularNoEmptyLifecycleMethod,
            RuleId::AngularUseLifecycleInterface,
        ]),
    );
    let lc_rules: Vec<RuleId> = lc_diags.iter().map(|d| d.rule).collect();
    assert!(lc_rules.contains(&RuleId::AngularNoAsyncLifecycleMethod));
    assert!(lc_rules.contains(&RuleId::AngularNoLifecycleCall));
    assert!(lc_rules.contains(&RuleId::AngularRequireLifecycleOnPrototype));
    assert!(lc_rules.contains(&RuleId::AngularNoEmptyLifecycleMethod));
    assert!(lc_rules.contains(&RuleId::AngularUseLifecycleInterface));
    // `async ngOnInit()` containing `await` must NOT emit a syntax-breaking autofix,
    // whereas an `async` lifecycle method without `await` does emit an autofix,
    // and arrow-function lifecycle properties preserve their parameters `(changes: SimpleChanges)`.
    let async_diag = lc_diags
        .iter()
        .find(|d| d.rule == RuleId::AngularNoAsyncLifecycleMethod)
        .unwrap();
    assert!(
        async_diag.autofix.is_none(),
        "Expected no autofix when async lifecycle body contains await"
    );
    let proto_changes = r#"
import { Component, ChangeDetectionStrategy, SimpleChanges } from '@angular/core';
@Component({
  selector: 'app-proto',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<p>Proto</p>`,
})
export class ProtoComponent {
  ngOnChanges = (changes: SimpleChanges): void => {
    console.log(changes);
  };
}
"#;
    let proto_diags = analyze_source(
        Path::new("src/proto.component.ts"),
        proto_changes,
        Some(&[RuleId::AngularRequireLifecycleOnPrototype]),
    );
    assert_eq!(proto_diags.len(), 1);
    let (fixed_proto, applied_proto) = apply_patches_to_source(proto_changes, &proto_diags);
    assert_eq!(applied_proto.len(), 1);
    assert!(
        fixed_proto.contains("ngOnChanges(changes: SimpleChanges)"),
        "Expected prototype conversion to preserve arrow function parameters, got:\n{fixed_proto}"
    );

    // 12. `angular-use-pipe-transform-interface`
    let bad_pipe = r#"
import { Pipe } from '@angular/core';

@Pipe({ name: 'shout' })
export class ShoutPipe {
  transform(value: string): string {
    return value.toUpperCase();
  }
}
"#;
    let pipe_diags = analyze_source(
        Path::new("src/shout.pipe.ts"),
        bad_pipe,
        Some(&[RuleId::AngularUsePipeTransformInterface]),
    );
    assert_eq!(pipe_diags.len(), 1);
    assert_eq!(pipe_diags[0].rule, RuleId::AngularUsePipeTransformInterface);

    let good_pipe = r#"
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({ name: 'shout' })
export class ShoutPipe implements PipeTransform {
  transform(value: string): string {
    return value.toUpperCase();
  }
}
"#;
    assert!(
        analyze_source(
            Path::new("src/shout.pipe.ts"),
            good_pipe,
            Some(&[RuleId::AngularUsePipeTransformInterface]),
        )
        .is_empty()
    );
}

#[test]
fn angular_performance_security_and_architecture_18_rules() {
    // 13. `angular-no-pipe-impure`
    let impure_pipe = r#"
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({ name: 'filterItems', pure: false, standalone: false })
export class FilterItemsPipe implements PipeTransform {
  transform(items: string[]): string[] {
    return items;
  }
}
"#;
    let pipe_diags = analyze_source(
        Path::new("src/filter-items.pipe.ts"),
        impure_pipe,
        Some(&[RuleId::AngularNoPipeImpure, RuleId::AngularPreferStandalone]),
    );
    assert_eq!(pipe_diags.len(), 2);

    // 14. `angular-no-output-native`, 15. `angular-no-output-on-prefix`,
    // 26. `angular-prefer-output-readonly`, 27. `angular-prefer-output-emitter-ref`
    let output_issues = r#"
import { Component, ChangeDetectionStrategy, Output, EventEmitter } from '@angular/core';
import { Subject } from 'rxjs';

@Component({
  selector: 'app-outputs',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<button>Click</button>`,
})
export class OutputsComponent {
  @Output() click = new EventEmitter<void>();
  @Output() readonly onSave = new EventEmitter<string>();
  @Output() readonly changed = new Subject<string>();
}
"#;
    let out_diags = analyze_source(
        Path::new("src/outputs.component.ts"),
        output_issues,
        Some(&[
            RuleId::AngularNoOutputNative,
            RuleId::AngularNoOutputOnPrefix,
            RuleId::AngularPreferOutputReadonly,
            RuleId::AngularPreferOutputEmitterRef,
        ]),
    );
    let out_rules: Vec<RuleId> = out_diags.iter().map(|d| d.rule).collect();
    assert!(out_rules.contains(&RuleId::AngularNoOutputNative));
    assert!(out_rules.contains(&RuleId::AngularNoOutputOnPrefix));
    assert!(out_rules.contains(&RuleId::AngularPreferOutputReadonly));
    assert!(out_rules.contains(&RuleId::AngularPreferOutputEmitterRef));

    // 16. `angular-relative-url-prefix`, 17. `angular-prefer-standalone`,
    // 21. `angular-no-duplicates-in-metadata-arrays`, 23. `angular-no-inputs-metadata-property`,
    // 24. `angular-no-outputs-metadata-property`, 25. `angular-no-queries-metadata-property`,
    // 28. `angular-use-component-view-encapsulation`, 30. `angular-component-max-inline-declarations`
    let metadata_issues = r#"
import { Component, ChangeDetectionStrategy, ViewEncapsulation, CommonModule } from '@angular/core';

@Component({
  selector: 'app-meta',
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  templateUrl: 'meta.component.html',
  styleUrls: ['/styles/meta.css'],
  imports: [CommonModule, CommonModule],
  inputs: ['id'],
  outputs: ['saved'],
  queries: { content: 'Child' },
  template: `
    <div>1</div>
    <div>2</div>
    <div>3</div>
    <div>4</div>
    <div>5</div>
    <div>6</div>
    <div>7</div>
    <div>8</div>
    <div>9</div>
    <div>10</div>
    <div>11</div>
    <div>12</div>
    <div>13</div>
    <div>14</div>
    <div>15</div>
    <div>16</div>
  `,
})
export class MetaComponent {}
"#;
    let meta_diags = analyze_source(
        Path::new("src/meta.component.ts"),
        metadata_issues,
        Some(&[
            RuleId::AngularRelativeUrlPrefix,
            RuleId::AngularPreferStandalone,
            RuleId::AngularNoDuplicatesInMetadataArrays,
            RuleId::AngularNoInputsMetadataProperty,
            RuleId::AngularNoOutputsMetadataProperty,
            RuleId::AngularNoQueriesMetadataProperty,
            RuleId::AngularUseComponentViewEncapsulation,
            RuleId::AngularComponentMaxInlineDeclarations,
        ]),
    );
    let meta_rules: Vec<RuleId> = meta_diags.iter().map(|d| d.rule).collect();
    assert!(meta_rules.contains(&RuleId::AngularRelativeUrlPrefix));
    assert!(meta_rules.contains(&RuleId::AngularPreferStandalone));
    assert!(meta_rules.contains(&RuleId::AngularNoDuplicatesInMetadataArrays));
    assert!(meta_rules.contains(&RuleId::AngularNoInputsMetadataProperty));
    assert!(meta_rules.contains(&RuleId::AngularNoOutputsMetadataProperty));
    assert!(meta_rules.contains(&RuleId::AngularNoQueriesMetadataProperty));
    assert!(meta_rules.contains(&RuleId::AngularUseComponentViewEncapsulation));
    assert!(meta_rules.contains(&RuleId::AngularComponentMaxInlineDeclarations));

    // 18. `angular-prefer-inject`, 19. `angular-use-injectable-provided-in`,
    // 20. `angular-prefer-host-metadata-property`, 22. `angular-no-forward-ref`,
    // 29. `angular-no-attribute-decorator`
    let di_and_host_issues = r#"
import { Component, Directive, Injectable, HostBinding, HostListener, Attribute, forwardRef, Inject } from '@angular/core';

@Injectable()
export class UnscopedService {}

@Directive({
  selector: '[appLegacyDir]',
  providers: [{ provide: UnscopedService, useExisting: forwardRef(() => UnscopedService) }],
})
export class LegacyDirective {
  @HostBinding('class.active') isActive = false;
  @HostListener('mouseenter') onEnter(): void {
    this.isActive = true;
  }

  constructor(
    private readonly svc: UnscopedService,
    @Attribute('mode') mode: string,
    @Inject('TOKEN') token: string,
  ) {
    console.log(mode, token);
  }
}
"#;
    let di_diags = analyze_source(
        Path::new("src/legacy.directive.ts"),
        di_and_host_issues,
        Some(&[
            RuleId::AngularPreferInject,
            RuleId::AngularUseInjectableProvidedIn,
            RuleId::AngularPreferHostMetadataProperty,
            RuleId::AngularNoForwardRef,
            RuleId::AngularNoAttributeDecorator,
        ]),
    );
    let di_rules: Vec<RuleId> = di_diags.iter().map(|d| d.rule).collect();
    assert!(di_rules.contains(&RuleId::AngularPreferInject));
    assert!(di_rules.contains(&RuleId::AngularUseInjectableProvidedIn));
    assert!(di_rules.contains(&RuleId::AngularPreferHostMetadataProperty));
    assert!(di_rules.contains(&RuleId::AngularNoForwardRef));
    assert!(di_rules.contains(&RuleId::AngularNoAttributeDecorator));
}

#[test]
fn angular_eslint_aliases_resolve_and_activate_detectors_via_analyze_source_with_config() {
    let aliases_and_rules = [
        ("@angular-eslint/no-uncalled-signals", RuleId::AngularNoUncalledSignals),
        ("@angular-eslint/prefer-signal-model", RuleId::AngularPreferSignalModel),
        ("@angular-eslint/prefer-signals", RuleId::AngularPreferSignals),
        ("@angular-eslint/no-conflicting-lifecycle", RuleId::AngularNoConflictingLifecycle),
        ("@angular-eslint/contextual-lifecycle", RuleId::AngularContextualLifecycle),
        ("@angular-eslint/contextual-decorator", RuleId::AngularContextualDecorator),
        ("@angular-eslint/no-async-lifecycle-method", RuleId::AngularNoAsyncLifecycleMethod),
        ("@angular-eslint/no-lifecycle-call", RuleId::AngularNoLifecycleCall),
        ("@angular-eslint/require-lifecycle-on-prototype", RuleId::AngularRequireLifecycleOnPrototype),
        ("@angular-eslint/no-empty-lifecycle-method", RuleId::AngularNoEmptyLifecycleMethod),
        ("@angular-eslint/use-lifecycle-interface", RuleId::AngularUseLifecycleInterface),
        ("@angular-eslint/use-pipe-transform-interface", RuleId::AngularUsePipeTransformInterface),
        ("@angular-eslint/no-pipe-impure", RuleId::AngularNoPipeImpure),
        ("@angular-eslint/no-output-native", RuleId::AngularNoOutputNative),
        ("@angular-eslint/no-output-on-prefix", RuleId::AngularNoOutputOnPrefix),
        ("@angular-eslint/relative-url-prefix", RuleId::AngularRelativeUrlPrefix),
        ("@angular-eslint/prefer-standalone", RuleId::AngularPreferStandalone),
        ("@angular-eslint/prefer-inject", RuleId::AngularPreferInject),
        ("@angular-eslint/use-injectable-provided-in", RuleId::AngularUseInjectableProvidedIn),
        ("@angular-eslint/prefer-host-metadata-property", RuleId::AngularPreferHostMetadataProperty),
        ("@angular-eslint/no-duplicates-in-metadata-arrays", RuleId::AngularNoDuplicatesInMetadataArrays),
        ("@angular-eslint/no-forward-ref", RuleId::AngularNoForwardRef),
        ("@angular-eslint/no-inputs-metadata-property", RuleId::AngularNoInputsMetadataProperty),
        ("@angular-eslint/no-outputs-metadata-property", RuleId::AngularNoOutputsMetadataProperty),
        ("@angular-eslint/no-queries-metadata-property", RuleId::AngularNoQueriesMetadataProperty),
        ("@angular-eslint/prefer-output-readonly", RuleId::AngularPreferOutputReadonly),
        ("@angular-eslint/prefer-output-emitter-ref", RuleId::AngularPreferOutputEmitterRef),
        ("@angular-eslint/use-component-view-encapsulation", RuleId::AngularUseComponentViewEncapsulation),
        ("@angular-eslint/no-attribute-decorator", RuleId::AngularNoAttributeDecorator),
        ("@angular-eslint/component-max-inline-declarations", RuleId::AngularComponentMaxInlineDeclarations),
    ];

    for (alias, expected_id) in aliases_and_rules {
        let parsed = RuleId::parse(alias)
            .unwrap_or_else(|| panic!("Expected alias {alias} to parse to {expected_id:?}"));
        assert_eq!(parsed, expected_id);
    }

    let parsed_uncalled = RuleId::parse("@angular-eslint/no-uncalled-signals").unwrap();
    let diags = analyze_source_with_config(
        Path::new("src/comp.component.ts"),
        r#"
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';
@Component({ selector: 'app-x', changeDetection: ChangeDetectionStrategy.OnPush, template: '' })
export class XComponent {
  flag = signal(true);
  test() { if (this.flag) { console.log('ok'); } }
}
"#,
        &DotoreConfig::default(),
        &CapabilityGate::default_angular(),
        Some(&[parsed_uncalled]),
    );
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].rule, RuleId::AngularNoUncalledSignals);
}

#[test]
fn valid_modern_angular_component_directive_pipe_and_service_produce_zero_diagnostics() {
    let valid_angular_suite = r#"
import {
  Component,
  Directive,
  Injectable,
  Pipe,
  PipeTransform,
  ChangeDetectionStrategy,
  OnInit,
  OnDestroy,
  signal,
  computed,
  input,
  model,
  output,
  inject,
} from '@angular/core';

@Injectable({ providedIn: 'root' })
export class MetricsService implements OnDestroy {
  readonly activeCount = signal(0);

  ngOnDestroy(): void {
    this.activeCount.set(0);
  }
}

@Pipe({ name: 'currencyLabel', pure: true })
export class CurrencyLabelPipe implements PipeTransform {
  transform(amount: number, symbol = '$'): string {
    return `${symbol}${amount.toFixed(2)}`;
  }
}

@Directive({
  selector: '[appTrackFocus]',
  host: {
    '[class.focused]': 'isFocused()',
    '(focus)': 'handleFocus()',
  },
})
export class TrackFocusDirective {
  readonly isFocused = signal(false);

  handleFocus(): void {
    this.isFocused.set(true);
  }
}

@Component({
  selector: 'app-checkout-summary',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CurrencyLabelPipe, TrackFocusDirective],
  templateUrl: './checkout-summary.component.html',
  styleUrls: ['./checkout-summary.component.css'],
})
export class CheckoutSummaryComponent implements OnInit, OnDestroy {
  private readonly metrics = inject(MetricsService);
  readonly subtotal = input.required<number>();
  readonly couponCode = model('');
  readonly checkoutConfirmed = output<number>();
  readonly total = computed(() => this.subtotal() * 1.08);

  ngOnInit(): void {
    if (this.total() > 0 && this.couponCode() !== '') {
      this.metrics.activeCount.update(c => c + 1);
    }
  }

  ngOnDestroy(): void {
    this.metrics.activeCount.update(c => Math.max(0, c - 1));
  }
}
"#;

    let diags = analyze_source_with_config(
        Path::new("src/checkout-summary.component.ts"),
        valid_angular_suite,
        &DotoreConfig::default(),
        &CapabilityGate::default_angular(),
        None,
    );
    let ng_diags: Vec<_> = diags
        .into_iter()
        .filter(|d| d.rule.as_str().starts_with("angular-"))
        .collect();
    assert!(
        ng_diags.is_empty(),
        "Expected 0 Angular diagnostics on clean modern Angular suite, got: {ng_diags:#?}"
    );
}
