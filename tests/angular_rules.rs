//! Integration tests for Ticket #11: Angular Support in `dotore-js`
//! - `Capability::Angular` and `Capability::Rxjs` inference from `package.json` and `angular.json`
//! - Non-activation of Angular rules on React-only packages and React rules on Angular-only packages
//! - Single-pass detectors for all 7 `angular-*` rules:
//!   1. `angular-no-signal-write-in-effect`
//!   2. `angular-rxjs-subscribe-requires-teardown`
//!   3. `angular-prefer-on-push-change-detection` (with deterministic `Autofix`)
//!   4. `angular-for-track-no-index`
//!   5. `angular-no-work-in-constructor`
//!   6. `angular-no-nested-subscribe`
//!   7. `angular-no-direct-native-element-mutation`

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, ContextualOwnerPolicy, DotoreConfig, JsLanguageAnalyzer,
    LanguageAnalyzer, PrescriptionTier, RuleCategory, RuleId, RulesListOptions,
    analyze_project_sources, analyze_source, analyze_source_with_config, apply_patches_to_source,
    build_rule_catalog, explain_rule,
};

#[test]
fn angular_capability_gate_inferred_from_package_json_and_angular_json() {
    let analyzer = JsLanguageAnalyzer::new();
    assert_eq!(
        analyzer.manifest_filenames(),
        &["package.json", "angular.json"]
    );

    // 1. `@angular/core` in package.json infers Angular, Rxjs, and TypeScript (not React)
    for pkg_dep in [
        r#""@angular/core": "^19.0.0""#,
        r#""@angular/common": "^19.0.0""#,
        r#""@angular/router": "^19.0.0""#,
        r#""@angular/platform-browser": "^19.0.0""#,
    ] {
        let pkg_json = format!(r#"{{ "name": "ng-app", "dependencies": {{ {pkg_dep} }} }}"#);
        let gate = CapabilityGate::from_package_json_str(&pkg_json);
        assert!(
            gate.has(Capability::Angular),
            "Expected Angular capability for {pkg_dep}"
        );
        assert!(
            gate.has(Capability::TypeScript),
            "Expected TypeScript capability for {pkg_dep}"
        );
        assert!(
            !gate.has(Capability::React),
            "Did not expect React capability for Angular-only package {pkg_dep}"
        );
    }

    // `@angular/core` also infers `Capability::Rxjs` alongside explicit `rxjs`
    let core_gate = CapabilityGate::from_package_json_str(
        r#"{ "name": "ng-core", "dependencies": { "@angular/core": "^19.0.0" } }"#,
    );
    assert!(core_gate.has(Capability::Angular));
    assert!(core_gate.has(Capability::Rxjs));

    let rxjs_only_gate = CapabilityGate::from_package_json_str(
        r#"{ "name": "rxjs-worker", "dependencies": { "rxjs": "^7.8.0" } }"#,
    );
    assert!(rxjs_only_gate.has(Capability::Rxjs));
    assert!(!rxjs_only_gate.has(Capability::Angular));
    assert!(!rxjs_only_gate.has(Capability::React));

    // 2. `angular.json` alone (without package.json) infers Angular, Rxjs, and TypeScript (not React)
    let angular_json = r#"{
        "$schema": "./node_modules/@angular/cli/lib/config/schema.json",
        "version": 1,
        "projects": {
            "portal": { "projectType": "application", "root": "" }
        }
    }"#;
    let ng_workspace_gate = analyzer.infer_capability_gate(
        Path::new("apps/portal"),
        &[(PathBuf::from("apps/portal/angular.json"), angular_json)],
    );
    assert!(ng_workspace_gate.has(Capability::Angular));
    assert!(ng_workspace_gate.has(Capability::Rxjs));
    assert!(ng_workspace_gate.has(Capability::TypeScript));
    assert!(!ng_workspace_gate.has(Capability::React));
}

#[test]
fn all_seven_angular_rules_registered_with_metadata_and_recipes() {
    let expected_rules = [
        (
            RuleId::AngularNoSignalWriteInEffect,
            "angular-no-signal-write-in-effect",
            RuleCategory::Performance,
            PrescriptionTier::Surgical,
        ),
        (
            RuleId::AngularRxjsSubscribeRequiresTeardown,
            "angular-rxjs-subscribe-requires-teardown",
            RuleCategory::Bugs,
            PrescriptionTier::Surgical,
        ),
        (
            RuleId::AngularPreferOnPushChangeDetection,
            "angular-prefer-on-push-change-detection",
            RuleCategory::Performance,
            PrescriptionTier::Autofix,
        ),
        (
            RuleId::AngularForTrackNoIndex,
            "angular-for-track-no-index",
            RuleCategory::Performance,
            PrescriptionTier::Surgical,
        ),
        (
            RuleId::AngularNoWorkInConstructor,
            "angular-no-work-in-constructor",
            RuleCategory::Bugs,
            PrescriptionTier::Surgical,
        ),
        (
            RuleId::AngularNoNestedSubscribe,
            "angular-no-nested-subscribe",
            RuleCategory::Bugs,
            PrescriptionTier::Surgical,
        ),
        (
            RuleId::AngularNoDirectNativeElementMutation,
            "angular-no-direct-native-element-mutation",
            RuleCategory::Bugs,
            PrescriptionTier::Surgical,
        ),
    ];

    let cfg = DotoreConfig::default();
    let ng_catalog = build_rule_catalog(
        &cfg,
        &RulesListOptions {
            framework: Some("angular".to_string()),
            ..RulesListOptions::default()
        },
    );
    assert_eq!(ng_catalog.len(), 7);

    for (rule_id, canonical_id, category, tier) in expected_rules {
        assert_eq!(RuleId::parse(canonical_id), Some(rule_id));
        assert_eq!(
            RuleId::parse(&format!("dotore/{canonical_id}")),
            Some(rule_id)
        );
        let meta = rule_id.metadata();
        assert_eq!(meta.canonical_id, canonical_id);
        assert_eq!(meta.category, category);
        assert_eq!(meta.default_tier, tier);
        assert!(meta.default_enabled);
        assert_eq!(meta.capability_gate.requires, &[Capability::Angular]);
        assert_eq!(meta.contextual_owner, ContextualOwnerPolicy::Subject);
        assert!(!meta.recipe_markdown.is_empty());

        let explained = explain_rule(canonical_id, &cfg)
            .unwrap_or_else(|| panic!("explain_rule({canonical_id}) returned None"));
        assert_eq!(explained.framework, "angular");
    }
}

#[test]
fn angular_no_signal_write_in_effect_flags_signal_writes_and_allows_computed() {
    let invalid_set = r#"
import { Component, ChangeDetectionStrategy, signal, effect } from '@angular/core';

@Component({
  selector: 'app-counter',
  template: `<p>{{ doubled() }}</p>`,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CounterComponent {
  count = signal(0);
  doubled = signal(0);

  constructor() {
    effect(() => {
      this.doubled.set(this.count() * 2);
    });
  }
}
"#;
    let diags = analyze_source(
        Path::new("src/counter.component.ts"),
        invalid_set,
        Some(&[RuleId::AngularNoSignalWriteInEffect]),
    );
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].rule, RuleId::AngularNoSignalWriteInEffect);
    assert_eq!(diags[0].subject_name.as_deref(), Some("CounterComponent"));
    assert_eq!(diags[0].target_name, "doubled");
    assert_eq!(diags[0].loc.line, 15);

    let invalid_update_and_allow = r#"
import { Component, ChangeDetectionStrategy, signal, effect } from '@angular/core';

@Component({
  selector: 'app-cart',
  template: `<span>{{ total() }}</span>`,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CartComponent {
  subtotal = signal(10);
  total = signal(10);

  constructor() {
    effect(() => {
      this.total.update(prev => prev + this.subtotal());
    }, { allowSignalWrites: true });
  }
}
"#;
    let update_diags = analyze_source(
        Path::new("src/cart.component.ts"),
        invalid_update_and_allow,
        Some(&[RuleId::AngularNoSignalWriteInEffect]),
    );
    assert_eq!(update_diags.len(), 1);
    assert_eq!(update_diags[0].rule, RuleId::AngularNoSignalWriteInEffect);
    assert_eq!(update_diags[0].target_name, "total");

    // Adversarial valid: computed() and non-signal side effects (logging, Map.set with 2 args)
    let valid_computed = r#"
import { Component, ChangeDetectionStrategy, signal, computed, effect } from '@angular/core';

@Component({
  selector: 'app-counter',
  template: `<p>{{ doubled() }}</p>`,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CounterComponent {
  count = signal(0);
  doubled = computed(() => this.count() * 2);
  private cache = new Map<number, number>();

  constructor() {
    effect(() => {
      console.debug('Current count:', this.count());
      this.cache.set(this.count(), this.doubled());
    });
  }
}
"#;
    let valid_diags = analyze_source(
        Path::new("src/counter.component.ts"),
        valid_computed,
        Some(&[RuleId::AngularNoSignalWriteInEffect]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics for computed() + Map.set(k, v), got: {valid_diags:#?}"
    );
}

#[test]
fn angular_rxjs_subscribe_requires_teardown_flags_leaks_and_allows_managed_streams() {
    let invalid_leak = r#"
import { Component, ChangeDetectionStrategy, OnInit, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-profile',
  template: `<p>{{ userId }}</p>`,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProfileComponent implements OnInit {
  private route = inject(ActivatedRoute);
  userId = '';

  ngOnInit(): void {
    this.route.paramMap.subscribe(params => {
      this.userId = params.get('id') ?? '';
    });
  }
}
"#;
    let diags = analyze_source(
        Path::new("src/profile.component.ts"),
        invalid_leak,
        Some(&[RuleId::AngularRxjsSubscribeRequiresTeardown]),
    );
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].rule, RuleId::AngularRxjsSubscribeRequiresTeardown);
    assert_eq!(diags[0].subject_name.as_deref(), Some("ProfileComponent"));
    assert_eq!(diags[0].loc.line, 15);

    // Adversarial valid cases:
    // 1. takeUntilDestroyed()
    // 2. takeUntil(this.destroy$)
    // 3. first() / take(1)
    // 4. Subscription stored and unsubscribed in ngOnDestroy()
    let valid_teardown = r#"
import { Component, ChangeDetectionStrategy, OnInit, OnDestroy, DestroyRef, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Subject, Subscription, first, take, takeUntil } from 'rxjs';

@Component({
  selector: 'app-stream-viewer',
  template: `<p>{{ status }}</p>`,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class StreamViewerComponent implements OnInit, OnDestroy {
  private destroyRef = inject(DestroyRef);
  private destroy$ = new Subject<void>();
  private sub = new Subscription();
  stream$ = new Subject<string>();
  status = '';

  ngOnInit(): void {
    this.stream$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(v => {
      this.status = v;
    });
    this.stream$.pipe(takeUntil(this.destroy$)).subscribe(v => {
      this.status = v;
    });
    this.stream$.pipe(first()).subscribe(v => {
      this.status = v;
    });
    this.stream$.pipe(take(1)).subscribe(v => {
      this.status = v;
    });
    this.sub.add(
      this.stream$.subscribe(v => {
        this.status = v;
      })
    );
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
    this.sub.unsubscribe();
  }
}
"#;
    let valid_diags = analyze_source(
        Path::new("src/stream-viewer.component.ts"),
        valid_teardown,
        Some(&[RuleId::AngularRxjsSubscribeRequiresTeardown]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics for properly torn-down subscriptions, got: {valid_diags:#?}"
    );
}

#[test]
fn angular_prefer_on_push_change_detection_and_autofix_round_trip() {
    // Case 1: Missing `changeDetection` property in `@Component({...})`
    let missing_on_push = r#"import { Component, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'app-user-card',
  template: `<div class="card">User</div>`
})
export class UserCardComponent {}
"#;
    let diags = analyze_source(
        Path::new("src/user-card.component.ts"),
        missing_on_push,
        Some(&[RuleId::AngularPreferOnPushChangeDetection]),
    );
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].rule, RuleId::AngularPreferOnPushChangeDetection);
    assert_eq!(diags[0].tier, PrescriptionTier::Autofix);
    assert!(diags[0].autofix.is_some());

    let (rewritten, descriptions) = apply_patches_to_source(missing_on_push, &diags);
    assert_eq!(descriptions.len(), 1);
    assert!(
        rewritten.contains("changeDetection: ChangeDetectionStrategy.OnPush"),
        "Expected rewritten source to contain OnPush, got:\n{rewritten}"
    );
    assert!(
        JsLanguageAnalyzer.validate_syntax(Path::new("src/user-card.component.ts"), &rewritten)
    );
    let reanalyzed = analyze_source(
        Path::new("src/user-card.component.ts"),
        &rewritten,
        Some(&[RuleId::AngularPreferOnPushChangeDetection]),
    );
    assert!(
        reanalyzed.is_empty(),
        "Expected 0 diagnostics after OnPush autofix, got: {reanalyzed:#?}"
    );

    // Case 2: Explicit `ChangeDetectionStrategy.Default` replaced with `ChangeDetectionStrategy.OnPush`
    let explicit_default = r#"import { Component, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'app-badge',
  template: `<span>Badge</span>`,
  changeDetection: ChangeDetectionStrategy.Default,
})
export class BadgeComponent {}
"#;
    let default_diags = analyze_source(
        Path::new("src/badge.component.ts"),
        explicit_default,
        Some(&[RuleId::AngularPreferOnPushChangeDetection]),
    );
    assert_eq!(default_diags.len(), 1);
    assert_eq!(default_diags[0].tier, PrescriptionTier::Autofix);
    let (rewritten_default, _) = apply_patches_to_source(explicit_default, &default_diags);
    assert!(rewritten_default.contains("changeDetection: ChangeDetectionStrategy.OnPush"));
    assert!(!rewritten_default.contains("ChangeDetectionStrategy.Default"));
    let reanalyzed_default = analyze_source(
        Path::new("src/badge.component.ts"),
        &rewritten_default,
        Some(&[RuleId::AngularPreferOnPushChangeDetection]),
    );
    assert!(reanalyzed_default.is_empty());
}

#[test]
fn angular_for_track_no_index_flags_index_and_identity_tracking_in_inline_and_html_templates() {
    let invalid_inline = r#"
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';

@Component({
  selector: 'app-todo-list',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <ul>
      @for (todo of todos(); track $index) {
        <li>{{ todo.title }}</li>
      }
    </ul>
    <div>
      @for (user of users(); track user) {
        <span>{{ user.name }}</span>
      }
    </div>
  `,
})
export class TodoListComponent {
  todos = signal([{ id: '1', title: 'Write tests' }]);
  users = signal([{ id: 'u1', name: 'Ada' }]);
}
"#;
    let inline_diags = analyze_source(
        Path::new("src/todo-list.component.ts"),
        invalid_inline,
        Some(&[RuleId::AngularForTrackNoIndex]),
    );
    assert_eq!(inline_diags.len(), 2);
    assert!(
        inline_diags
            .iter()
            .all(|d| d.rule == RuleId::AngularForTrackNoIndex)
    );

    // Also test external `.html` template file directly
    let invalid_html = r#"
<section>
  @for (item of items; let idx = $index; track idx) {
    <article>{{ item.label }}</article>
  }
</section>
"#;
    let html_diags = analyze_source(
        Path::new("src/todo-list.component.html"),
        invalid_html,
        Some(&[RuleId::AngularForTrackNoIndex]),
    );
    assert_eq!(html_diags.len(), 1);
    assert_eq!(html_diags[0].rule, RuleId::AngularForTrackNoIndex);

    // Adversarial valid: `track todo.id` and `track trackById($index, user)`
    let valid_inline = r#"
import { Component, ChangeDetectionStrategy, signal } from '@angular/core';

@Component({
  selector: 'app-todo-list',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <ul>
      @for (todo of todos(); track todo.id) {
        <li>{{ todo.title }}</li>
      }
      @for (user of users(); track trackByUser($index, user)) {
        <li>{{ user.name }}</li>
      }
    </ul>
  `,
})
export class TodoListComponent {
  todos = signal([{ id: '1', title: 'Ship Angular support' }]);
  users = signal([{ id: 'u1', name: 'Grace' }]);
  trackByUser(_index: number, user: { id: string }) {
    return user.id;
  }
}
"#;
    let valid_diags = analyze_source(
        Path::new("src/todo-list.component.ts"),
        valid_inline,
        Some(&[RuleId::AngularForTrackNoIndex]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics for stable `track todo.id`, got: {valid_diags:#?}"
    );
}

#[test]
fn angular_constructor_nested_subscribe_and_native_element_rules() {
    // 5. `angular-no-work-in-constructor`
    let invalid_ctor = r#"
import { Component, ChangeDetectionStrategy } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-orders',
  template: `<div>Orders</div>`,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrdersComponent {
  orders: unknown[] = [];
  constructor(private http: HttpClient) {
    this.http.get<unknown[]>('/api/orders').subscribe(data => {
      this.orders = data;
    });
  }
}
"#;
    let ctor_diags = analyze_source(
        Path::new("src/orders.component.ts"),
        invalid_ctor,
        Some(&[RuleId::AngularNoWorkInConstructor]),
    );
    assert_eq!(ctor_diags.len(), 1);
    assert_eq!(ctor_diags[0].rule, RuleId::AngularNoWorkInConstructor);
    assert_eq!(ctor_diags[0].subject_name.as_deref(), Some("OrdersComponent"));

    // Valid: work moved to `ngOnInit` and lightweight `inject()` in field initializer
    let valid_ctor = r#"
import { Component, ChangeDetectionStrategy, OnInit, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

@Component({
  selector: 'app-orders',
  template: `<div>Orders</div>`,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrdersComponent implements OnInit {
  private http = inject(HttpClient);
  orders: unknown[] = [];

  constructor() {}

  ngOnInit(): void {
    this.http.get<unknown[]>('/api/orders').pipe(takeUntilDestroyed()).subscribe(data => {
      this.orders = data;
    });
  }
}
"#;
    let valid_ctor_diags = analyze_source(
        Path::new("src/orders.component.ts"),
        valid_ctor,
        Some(&[RuleId::AngularNoWorkInConstructor]),
    );
    assert!(valid_ctor_diags.is_empty());

    // 6. `angular-no-nested-subscribe`
    let invalid_nested = r#"
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({ providedIn: 'root' })
export class OrderDetailsService {
  private http = inject(HttpClient);

  loadOrderWithCustomer(orderId: string): void {
    this.http.get<{ customerId: string }>(`/api/orders/${orderId}`).subscribe(order => {
      this.http.get(`/api/customers/${order.customerId}`).subscribe(customer => {
        console.log(customer);
      });
    });
  }
}
"#;
    let nested_diags = analyze_source(
        Path::new("src/order-details.service.ts"),
        invalid_nested,
        Some(&[RuleId::AngularNoNestedSubscribe]),
    );
    assert_eq!(nested_diags.len(), 1);
    assert_eq!(nested_diags[0].rule, RuleId::AngularNoNestedSubscribe);
    assert_eq!(
        nested_diags[0].subject_name.as_deref(),
        Some("OrderDetailsService")
    );

    // Valid: flattened with `switchMap`
    let valid_switch_map = r#"
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { switchMap } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

@Injectable({ providedIn: 'root' })
export class OrderDetailsService {
  private http = inject(HttpClient);

  loadOrderWithCustomer(orderId: string) {
    return this.http.get<{ customerId: string }>(`/api/orders/${orderId}`).pipe(
      switchMap(order => this.http.get(`/api/customers/${order.customerId}`)),
      takeUntilDestroyed(),
    ).subscribe();
  }
}
"#;
    let valid_nested_diags = analyze_source(
        Path::new("src/order-details.service.ts"),
        valid_switch_map,
        Some(&[RuleId::AngularNoNestedSubscribe]),
    );
    assert!(valid_nested_diags.is_empty());

    // 7. `angular-no-direct-native-element-mutation`
    let invalid_dom = r#"
import { Directive, ElementRef, AfterViewInit, inject } from '@angular/core';

@Directive({ selector: '[appHighlight]' })
export class HighlightDirective implements AfterViewInit {
  private el = inject(ElementRef);

  ngAfterViewInit(): void {
    this.el.nativeElement.style.backgroundColor = 'yellow';
    this.el.nativeElement.classList.add('highlighted');
  }
}
"#;
    let dom_diags = analyze_source(
        Path::new("src/highlight.directive.ts"),
        invalid_dom,
        Some(&[RuleId::AngularNoDirectNativeElementMutation]),
    );
    assert_eq!(dom_diags.len(), 2);
    assert!(
        dom_diags
            .iter()
            .all(|d| d.rule == RuleId::AngularNoDirectNativeElementMutation)
    );
    assert_eq!(
        dom_diags[0].subject_name.as_deref(),
        Some("HighlightDirective")
    );

    // Valid: `Renderer2` and read-only measurement
    let valid_renderer = r#"
import { Directive, ElementRef, Renderer2, AfterViewInit, inject } from '@angular/core';

@Directive({ selector: '[appHighlight]' })
export class HighlightDirective implements AfterViewInit {
  private el = inject(ElementRef);
  private renderer = inject(Renderer2);

  ngAfterViewInit(): void {
    const rect = this.el.nativeElement.getBoundingClientRect();
    if (rect.width > 0) {
      this.renderer.setStyle(this.el.nativeElement, 'background-color', 'yellow');
      this.renderer.addClass(this.el.nativeElement, 'highlighted');
    }
  }
}
"#;
    let valid_dom_diags = analyze_source(
        Path::new("src/highlight.directive.ts"),
        valid_renderer,
        Some(&[RuleId::AngularNoDirectNativeElementMutation]),
    );
    assert!(valid_dom_diags.is_empty());
}

#[test]
fn angular_project_capability_gate_activates_on_angular_manifests_and_skips_react_packages() {
    let angular_component_src = r#"
import { Component, signal, effect } from '@angular/core';

@Component({
  selector: 'app-dashboard',
  template: `
    @for (item of items(); track $index) {
      <div>{{ item.name }}</div>
    }
  `,
})
export class DashboardComponent {
  items = signal([{ id: 1, name: 'Alpha' }]);
  count = signal(0);

  constructor() {
    effect(() => {
      this.count.set(this.items().length);
    });
  }
}
"#;

    // 1. React-only package must NOT activate Angular rules when `enabled_rules` is `None`
    let react_only_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{ "name": "react-web", "dependencies": { "react": "^19.0.0" } }"#.to_string(),
            ),
            (
                PathBuf::from("src/dashboard.component.ts"),
                angular_component_src.to_string(),
            ),
        ],
        None,
    );
    assert!(
        !react_only_report.diagnostics.iter().any(|d| {
            d.rule
                .as_str()
                .starts_with("angular-")
        }),
        "Expected zero Angular diagnostics in React-only package, got: {:#?}",
        react_only_report.diagnostics
    );

    // Also verify `analyze_source_with_config` with a React-only gate does not emit Angular rules
    let react_gate_diags = analyze_source_with_config(
        Path::new("src/dashboard.component.ts"),
        angular_component_src,
        &DotoreConfig::default(),
        &CapabilityGate::default_react(),
        None,
    );
    assert!(
        !react_gate_diags
            .iter()
            .any(|d| d.rule.as_str().starts_with("angular-"))
    );

    // 2. Angular `package.json` activates Angular rules automatically with `enabled_rules = None`
    let ng_pkg_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{ "name": "ng-web", "dependencies": { "@angular/core": "^19.0.0", "rxjs": "^7.8.0" } }"#.to_string(),
            ),
            (
                PathBuf::from("src/dashboard.component.ts"),
                angular_component_src.to_string(),
            ),
        ],
        None,
    );
    let ng_rules: Vec<RuleId> = ng_pkg_report.diagnostics.iter().map(|d| d.rule).collect();
    assert!(ng_rules.contains(&RuleId::AngularPreferOnPushChangeDetection));
    assert!(ng_rules.contains(&RuleId::AngularForTrackNoIndex));
    assert!(ng_rules.contains(&RuleId::AngularNoSignalWriteInEffect));

    // 3. `angular.json` workspace manifest activates Angular rules even without `@angular/core` in package.json
    let ng_json_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("angular.json"),
                r#"{ "version": 1, "projects": { "dashboard": { "root": "" } } }"#.to_string(),
            ),
            (
                PathBuf::from("src/dashboard.component.ts"),
                angular_component_src.to_string(),
            ),
        ],
        None,
    );
    let ng_json_rules: Vec<RuleId> = ng_json_report.diagnostics.iter().map(|d| d.rule).collect();
    assert!(ng_json_rules.contains(&RuleId::AngularPreferOnPushChangeDetection));
    assert!(ng_json_rules.contains(&RuleId::AngularForTrackNoIndex));
    assert!(ng_json_rules.contains(&RuleId::AngularNoSignalWriteInEffect));
}
