//! Integration tests for Ticket #53:
//! 1. 8 Angular HTML Template Type-Safety & Accessibility Rules (`.component.html` + inline `template`)
//! 2. 7 NgRx & Angular Material Rules + Capability Gate activation & silence
//! 3. Angular `ProjectGraph` Entrypoints (`*.module.ts`, `*.routes.ts`, `*.config.ts`, `angular.json`),
//!    lazy route edges (`loadComponent`, `loadChildren`, `templateUrl`, `styleUrl`, `styleUrls`),
//!    and implicit Angular toolchain dependencies.

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, RuleId, analyze_project_sources, analyze_source,
    analyze_source_with_config, apply_patches_to_source,
};

#[test]
fn angular_template_all_eight_rules_detect_violations_in_inline_and_external_html_and_allow_accessible_bindings()
 {
    let all_template_rules = [
        RuleId::AngularTemplateNoAny,
        RuleId::AngularTemplateAltText,
        RuleId::AngularTemplateClickEventsHaveKeyEvents,
        RuleId::AngularTemplateMouseEventsHaveKeyEvents,
        RuleId::AngularTemplateElementsHaveContent,
        RuleId::AngularTemplateInteractiveSupportsFocus,
        RuleId::AngularTemplateTableScope,
        RuleId::AngularTemplateValidAria,
    ];

    let invalid_html = r#"
<section>
  <p>{{ $any(user).fullName }}</p>
  <img src="/avatar.png" />
  <area shape="rect" coords="0,0,10,10" href="/map" />
  <input type="image" src="/submit.png" />
  <object data="/movie.swf"></object>
  <div (click)="selectUser()">Select</div>
  <span (mouseover)="showPreview()" (mouseout)="hidePreview()">Hover</span>
  <h2></h2>
  <a href="/profile"></a>
  <div role="button" (click)="openMenu()" (keydown.enter)="openMenu()">Menu</div>
  <table>
    <tr>
      <td scope="col">Cell</td>
    </tr>
  </table>
  <button aria-labelled-by="title-id" [attr.aria-role]="'button'">Save</button>
</section>
"#;

    // 1. External `.component.html` file
    let html_diags = analyze_source(
        Path::new("src/user-card.component.html"),
        invalid_html,
        Some(&all_template_rules),
    );
    let html_rules: Vec<RuleId> = html_diags.iter().map(|d| d.rule).collect();
    for expected in all_template_rules {
        assert!(
            html_rules.contains(&expected),
            "Expected {expected:?} in external .component.html diagnostics, got: {html_diags:#?}"
        );
    }

    // Also verify plain `.html` without `@for` is recognized by `analyze_source`
    let plain_html_diags = analyze_source(
        Path::new("src/template.html"),
        invalid_html,
        Some(&all_template_rules),
    );
    let plain_html_rules: Vec<RuleId> = plain_html_diags.iter().map(|d| d.rule).collect();
    for expected in all_template_rules {
        assert!(
            plain_html_rules.contains(&expected),
            "Expected {expected:?} in plain .html diagnostics, got: {plain_html_diags:#?}"
        );
    }

    // 2. Inline `@Component({ template })` string
    let inline_component = format!(
        r#"
import {{ Component, ChangeDetectionStrategy }} from '@angular/core';

@Component({{
  selector: 'app-user-card',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `{invalid_html}`,
}})
export class UserCardComponent {{}}
"#
    );
    let inline_diags = analyze_source(
        Path::new("src/user-card.component.ts"),
        &inline_component,
        Some(&all_template_rules),
    );
    let inline_rules: Vec<RuleId> = inline_diags.iter().map(|d| d.rule).collect();
    for expected in all_template_rules {
        assert!(
            inline_rules.contains(&expected),
            "Expected {expected:?} in inline @Component template diagnostics, got: {inline_diags:#?}"
        );
    }
    assert!(
        inline_diags
            .iter()
            .all(|d| d.subject_name.as_deref() == Some("UserCardComponent")),
        "Expected all inline template diagnostics to attach to UserCardComponent, got: {inline_diags:#?}"
    );

    // Verify autofix on `angular-template-table-scope` removes invalid `scope` from `<td>`
    let scope_html = "<table><tr><td scope=\"col\">Value</td></tr></table>";
    let scope_diags = analyze_source(
        Path::new("src/table.component.html"),
        scope_html,
        Some(&[RuleId::AngularTemplateTableScope]),
    );
    assert_eq!(scope_diags.len(), 1);
    let (fixed_scope, applied_scope) = apply_patches_to_source(scope_html, &scope_diags);
    assert_eq!(applied_scope.len(), 1);
    assert_eq!(fixed_scope, "<table><tr><td>Value</td></tr></table>");

    // 3. Valid accessible bindings must produce 0 diagnostics across all 8 rules
    let valid_html = r#"
<section>
  <p>{{ user.fullName }}</p>
  <img [alt]="user.name" src="/avatar.png" />
  <img [attr.alt]="user.altText" src="/banner.png" />
  <area shape="rect" coords="0,0,10,10" href="/map" [attr.aria-label]="'Region'" />
  <input type="image" src="/submit.png" alt="Submit form" />
  <object data="/movie.swf" aria-label="Intro video"></object>
  <object data="/chart.svg"><span>Fallback chart description</span></object>
  <button (click)="selectUser()">Select</button>
  <div (click)="selectUser()" (keydown.enter)="selectUser()" role="button" tabindex="0">Select</div>
  <div (click)="selectUser()" (keyup)="selectUser()" role="button" [attr.tabindex]="0">Select 2</div>
  <span (mouseover)="showPreview()" (focus)="showPreview()" (mouseout)="hidePreview()" (blur)="hidePreview()">Hover</span>
  <h2>Dashboard</h2>
  <h3 [innerHTML]="headingHtml"></h3>
  <a href="/profile" [attr.aria-label]="profileLabel"></a>
  <a href="/home"><ng-content></ng-content></a>
  <table>
    <thead>
      <tr>
        <th scope="col">Name</th>
        <th [attr.scope]="'row'">ID</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Alice</td>
        <td>42</td>
      </tr>
    </tbody>
  </table>
  <button aria-labelledby="title-id" [attr.aria-expanded]="isOpen">Toggle</button>
</section>
"#;
    let valid_html_diags = analyze_source(
        Path::new("src/user-card.component.html"),
        valid_html,
        Some(&all_template_rules),
    );
    assert!(
        valid_html_diags.is_empty(),
        "Expected 0 diagnostics on accessible Angular template, got: {valid_html_diags:#?}"
    );
}

#[test]
fn ngrx_and_angular_material_all_seven_rules_detect_violations_and_apply_autofixes() {
    let ngrx_and_mat_rules = [
        RuleId::NgrxNoMultipleActionsInEffects,
        RuleId::NgrxNoEffectDecoratorAndCreator,
        RuleId::NgrxNoCyclicActionCreators,
        RuleId::NgrxNoTypedGlobalStore,
        RuleId::NgrxOnFunctionExplicitReturnType,
        RuleId::NgrxSelectStyle,
        RuleId::AngularMaterialNoConflictingMixins,
    ];

    // Check alias parsing for all 15 rules in Ticket #53
    for (alias, expected) in [
        ("@angular-eslint/template/no-any", RuleId::AngularTemplateNoAny),
        ("@angular-eslint/template/alt-text", RuleId::AngularTemplateAltText),
        (
            "@angular-eslint/template/click-events-have-key-events",
            RuleId::AngularTemplateClickEventsHaveKeyEvents,
        ),
        (
            "@angular-eslint/template/mouse-events-have-key-events",
            RuleId::AngularTemplateMouseEventsHaveKeyEvents,
        ),
        (
            "@angular-eslint/template/elements-have-content",
            RuleId::AngularTemplateElementsHaveContent,
        ),
        (
            "@angular-eslint/template/interactive-supports-focus",
            RuleId::AngularTemplateInteractiveSupportsFocus,
        ),
        (
            "@angular-eslint/template/table-scope",
            RuleId::AngularTemplateTableScope,
        ),
        (
            "@angular-eslint/template/valid-aria",
            RuleId::AngularTemplateValidAria,
        ),
        (
            "@ngrx/no-multiple-actions-in-effects",
            RuleId::NgrxNoMultipleActionsInEffects,
        ),
        (
            "@ngrx/no-effect-decorator-and-creator",
            RuleId::NgrxNoEffectDecoratorAndCreator,
        ),
        (
            "@ngrx/no-effect-decorator",
            RuleId::NgrxNoEffectDecoratorAndCreator,
        ),
        (
            "@ngrx/no-cyclic-action-creators",
            RuleId::NgrxNoCyclicActionCreators,
        ),
        ("@ngrx/no-typed-global-store", RuleId::NgrxNoTypedGlobalStore),
        (
            "@ngrx/on-function-explicit-return-type",
            RuleId::NgrxOnFunctionExplicitReturnType,
        ),
        ("@ngrx/select-style", RuleId::NgrxSelectStyle),
        (
            "@angular/material/no-conflicting-mixins",
            RuleId::AngularMaterialNoConflictingMixins,
        ),
    ] {
        assert_eq!(
            RuleId::parse(alias),
            Some(expected),
            "Expected alias {alias} to resolve to {expected:?}"
        );
    }

    let invalid_ngrx_and_mat = r#"
import { Component, Injectable, ChangeDetectionStrategy, inject } from '@angular/core';
import { Store, select, createReducer, on, createAction } from '@ngrx/store';
import { Actions, createEffect, ofType, Effect } from '@ngrx/effects';
import { switchMap, map } from 'rxjs/operators';

export const loadUsers = createAction('[Users] Load');
export const loadUsersSuccess = createAction('[Users] Load Success');
export const notifyLoaded = createAction('[Users] Notify Loaded');

export interface AppState {
  users: string[];
}

export const usersReducer = createReducer(
  { users: [] as string[] },
  on(loadUsers, (state) => ({ ...state })),
);

@Injectable({ providedIn: 'root' })
export class UsersEffects {
  private readonly actions$ = inject(Actions);

  @Effect()
  legacyEffect$ = createEffect(() =>
    this.actions$.pipe(
      ofType(loadUsers),
      switchMap(() => [loadUsersSuccess(), notifyLoaded()]),
    ),
  );

  cyclicEffect$ = createEffect(() =>
    this.actions$.pipe(
      ofType(loadUsers),
      map(() => loadUsers()),
    ),
  );
}

@Component({
  selector: 'app-users-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<button mat-button mat-raised-button>Save</button>`,
  styles: [`
    @use '@angular/material' as mat;
    @include mat.all-component-themes($theme);
    @include mat.button-theme($theme);
  `],
})
export class UsersPageComponent {
  private readonly store: Store<AppState> = inject(Store);
  users$ = this.store.pipe(select('users'));
   legacyUsers$ = this.store.select('users');
}
"#;

    let diags = analyze_source(
        Path::new("src/users.effects.ts"),
        invalid_ngrx_and_mat,
        Some(&ngrx_and_mat_rules),
    );
    let found_rules: Vec<RuleId> = diags.iter().map(|d| d.rule).collect();
    for expected in ngrx_and_mat_rules {
        assert!(
            found_rules.contains(&expected),
            "Expected {expected:?} in NgRx/Material diagnostics, got: {diags:#?}"
        );
    }

    // Verify autofix for `ngrx-no-typed-global-store`
    let typed_store_src = "import { Store } from '@ngrx/store';\nexport class UsersFacade {\n  constructor(private store: Store<AppState>) {}\n}\n";
    let store_diags = analyze_source(
        Path::new("src/users.facade.ts"),
        typed_store_src,
        Some(&[RuleId::NgrxNoTypedGlobalStore]),
    );
    assert_eq!(store_diags.len(), 1);
    let (fixed_store, applied_store) = apply_patches_to_source(typed_store_src, &store_diags);
    assert_eq!(applied_store.len(), 1);
    assert!(
        fixed_store.contains("private store: Store)"),
        "Expected generic type argument to be removed, got: {fixed_store}"
    );

    // Valid NgRx + Angular Material usage produces 0 diagnostics
    let valid_ngrx_and_mat = r#"
import { Component, Injectable, ChangeDetectionStrategy, inject } from '@angular/core';
import { Store, createReducer, on, createAction, createFeatureSelector } from '@ngrx/store';
import { Actions, createEffect, ofType } from '@ngrx/effects';
import { map } from 'rxjs/operators';

export const loadUsers = createAction('[Users] Load');
export const loadUsersSuccess = createAction('[Users] Load Success');

export interface UsersState {
  users: string[];
}

export const selectUsersState = createFeatureSelector<UsersState>('users');

export const usersReducer = createReducer(
  { users: [] as string[] },
  on(loadUsers, (state): UsersState => ({ ...state })),
);

@Injectable({ providedIn: 'root' })
export class UsersEffects {
  private readonly actions$ = inject(Actions);

  loadUsers$ = createEffect(() =>
    this.actions$.pipe(
      ofType(loadUsers),
      map(() => loadUsersSuccess()),
    ),
  );

  logLoadUsers$ = createEffect(
    () =>
      this.actions$.pipe(
        ofType(loadUsers),
        map(() => loadUsers()),
      ),
    { dispatch: false },
  );
}

@Component({
  selector: 'app-users-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<button mat-raised-button>Save</button>`,
  styles: [`
    @use '@angular/material' as mat;
    @include mat.all-component-themes($theme);
  `],
})
export class UsersPageComponent {
  private readonly store = inject(Store);
  users = this.store.selectSignal(selectUsersState);
}
"#;
    let valid_diags = analyze_source(
        Path::new("src/users.effects.ts"),
        valid_ngrx_and_mat,
        Some(&ngrx_and_mat_rules),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on valid NgRx & Material code, got: {valid_diags:#?}"
    );
}

#[test]
fn ngrx_and_material_rules_respect_capability_gate_in_project_scans() {
    let effects_and_mat_code = r#"
import { Component, Injectable, ChangeDetectionStrategy, inject } from '@angular/core';
import { Store, createReducer, on, createAction } from '@ngrx/store';
import { Actions, createEffect, ofType } from '@ngrx/effects';
import { map } from 'rxjs/operators';

export const ping = createAction('[App] Ping');
export const reducer = createReducer({}, on(ping, (state) => state));

@Injectable({ providedIn: 'root' })
export class AppEffects {
  private readonly actions$ = inject(Actions);
  cyclic$ = createEffect(() => this.actions$.pipe(ofType(ping), map(() => ping())));
}

@Component({
  selector: 'app-root',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<button mat-button mat-raised-button>Go</button>`,
})
export class AppComponent {
  private readonly store: Store<{ count: number }> = inject(Store);
}
"#;

    // 1. Plain Angular project WITHOUT `@ngrx/*` or `@angular/material` in `package.json`:
    //    NgRx and Angular Material rules must remain silent when `enabled_rules` is `None`.
    let plain_angular_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                  "name": "plain-ng",
                  "dependencies": {
                    "@angular/core": "^19.0.0",
                    "rxjs": "^7.8.0"
                  }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/app.component.ts"),
                effects_and_mat_code.to_string(),
            ),
        ],
        None,
    );
    assert!(
        !plain_angular_report.diagnostics.iter().any(|d| {
            d.rule.as_str().starts_with("ngrx-")
                || d.rule.as_str().starts_with("angular-material-")
        }),
        "Expected 0 NgRx/Material diagnostics on plain Angular project without @ngrx/* or @angular/material, got: {:#?}",
        plain_angular_report.diagnostics
    );

    // Also verify `analyze_source_with_config` with a gate that only has `Capability::Angular`
    let ng_only_gate = CapabilityGate::with_capabilities([
        Capability::Angular,
        Capability::Rxjs,
        Capability::TypeScript,
    ]);
    let ng_only_diags = analyze_source_with_config(
        Path::new("src/app/app.component.ts"),
        effects_and_mat_code,
        &DotoreConfig::default(),
        &ng_only_gate,
        None,
    );
    assert!(
        !ng_only_diags.iter().any(|d| {
            d.rule.as_str().starts_with("ngrx-")
                || d.rule.as_str().starts_with("angular-material-")
        }),
        "Expected 0 NgRx/Material diagnostics with Angular-only gate, got: {ng_only_diags:#?}"
    );

    // 2. Angular project WITH `@ngrx/store`, `@ngrx/effects`, and `@angular/material`:
    //    All relevant NgRx and Angular Material rules must activate automatically when `enabled_rules` is `None`.
    let full_ng_report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                  "name": "enterprise-ng",
                  "dependencies": {
                    "@angular/core": "^19.0.0",
                    "@angular/material": "^19.0.0",
                    "@ngrx/store": "^19.0.0",
                    "@ngrx/effects": "^19.0.0",
                    "rxjs": "^7.8.0"
                  }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/app.component.ts"),
                effects_and_mat_code.to_string(),
            ),
        ],
        None,
    );
    let active_rules: Vec<RuleId> = full_ng_report.diagnostics.iter().map(|d| d.rule).collect();
    assert!(active_rules.contains(&RuleId::NgrxNoCyclicActionCreators));
    assert!(active_rules.contains(&RuleId::NgrxNoTypedGlobalStore));
    assert!(active_rules.contains(&RuleId::NgrxOnFunctionExplicitReturnType));
    assert!(active_rules.contains(&RuleId::AngularMaterialNoConflictingMixins));
}

#[test]
fn angular_project_graph_entrypoints_lazy_routes_and_implicit_deps_report_zero_false_positives() {
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                  "name": "ng-enterprise-portal",
                  "dependencies": {
                    "@angular/animations": "^19.0.0",
                    "@angular/common": "^19.0.0",
                    "@angular/compiler": "^19.0.0",
                    "@angular/core": "^19.0.0",
                    "@angular/forms": "^19.0.0",
                    "@angular/platform-browser": "^19.0.0",
                    "@angular/platform-browser-dynamic": "^19.0.0",
                    "@angular/router": "^19.0.0",
                    "rxjs": "^7.8.0",
                    "zone.js": "~0.15.0"
                  },
                  "devDependencies": {
                    "@angular-devkit/build-angular": "^19.0.0",
                    "@angular/build": "^19.0.0",
                    "@angular/cli": "^19.0.0",
                    "@angular/compiler-cli": "^19.0.0",
                    "typescript": "~5.6.0"
                  }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("angular.json"),
                r#"{
                  "version": 1,
                  "projects": {
                    "portal": {
                      "projectType": "application",
                      "root": "",
                      "sourceRoot": "src",
                      "architect": {
                        "build": {
                          "options": {
                            "browser": "src/bootstrap.ts",
                            "server": "src/bootstrap.server.ts"
                          }
                        }
                      }
                    }
                  }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("src/bootstrap.ts"),
                r#"
import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';

bootstrapApplication(AppComponent, appConfig);
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/bootstrap.server.ts"),
                r#"
import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';

export const bootstrap = () => bootstrapApplication(AppComponent, appConfig);
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/app.config.ts"),
                r#"
import { ApplicationConfig } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';

export const appConfig: ApplicationConfig = {
  providers: [provideRouter(routes)],
};
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/app.routes.ts"),
                r#"
import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: 'billing',
    loadComponent: () =>
      import('./features/billing/billing.component').then(m => m.BillingComponent),
  },
  {
    path: 'settings',
    loadChildren: () =>
      import('./features/settings/settings.routes').then(m => m.SETTINGS_ROUTES),
  },
  {
    path: 'legacy',
    loadChildren: './features/legacy/legacy.module#LegacyModule',
  },
];
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/app.component.ts"),
                r#"
import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
})
export class AppComponent {}
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/app.component.html"),
                "<main><router-outlet></router-outlet></main>".to_string(),
            ),
            (
                PathBuf::from("src/app/app.component.css"),
                "main { display: block; }".to_string(),
            ),
            (
                PathBuf::from("src/app/features/billing/billing.component.ts"),
                r#"
import { Component, ChangeDetectionStrategy } from '@angular/core';
import { formatInvoiceAmount } from './billing.utils';

@Component({
  selector: 'app-billing',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<p>{{ total }}</p>`,
  styleUrls: ['./billing.component.css'],
})
export class BillingComponent {
  readonly total = formatInvoiceAmount(120);
}
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/features/billing/billing.utils.ts"),
                "export function formatInvoiceAmount(amount: number): string { return `$${amount}`; }\n"
                    .to_string(),
            ),
            (
                PathBuf::from("src/app/features/billing/billing.component.css"),
                "p { font-weight: 600; }".to_string(),
            ),
            (
                PathBuf::from("src/app/features/settings/settings.routes.ts"),
                r#"
import { Routes } from '@angular/router';
import { SettingsComponent } from './settings.component';

export const SETTINGS_ROUTES: Routes = [
  { path: '', component: SettingsComponent },
];
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/features/settings/settings.component.ts"),
                r#"
import { Component, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'app-settings',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<section>Settings</section>`,
})
export class SettingsComponent {}
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/features/legacy/legacy.module.ts"),
                r#"
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

@NgModule({
  imports: [CommonModule],
})
export class LegacyModule {}
"#
                .to_string(),
            ),
        ],
        Some(&[
            RuleId::UnusedFile,
            RuleId::UnusedExport,
            RuleId::UnusedDependency,
            RuleId::UnusedDevDependency,
        ]),
    );

    assert!(
        report.diagnostics.is_empty(),
        "Expected 0 dead-code / unused-dependency diagnostics on valid Angular workspace, got: {:#?}",
        report.diagnostics
    );
    // Verify that real dead code (orphan file, unused export, unused dependency) in the same Angular workspace IS caught
    let report_with_dead_code = analyze_project_sources(
        vec![
            (
                PathBuf::from("package.json"),
                r#"{
                  "name": "ng-enterprise-portal",
                  "dependencies": {
                    "@angular/core": "^19.0.0",
                    "zone.js": "~0.15.0",
                    "unused-third-party-pkg": "^1.0.0"
                  }
                }"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/app.config.ts"),
                r#"
import { routes } from './app.routes';
export const appConfig = { routes };
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/app.routes.ts"),
                r#"
export const routes = [
  {
    path: 'billing',
    loadComponent: () => import('./billing.component').then(m => m.BillingComponent),
  },
];
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/billing.component.ts"),
                r#"
import { usedHelper } from './billing.utils';
export class BillingComponent { val = usedHelper(); }
"#
                .to_string(),
            ),
            (
                PathBuf::from("src/app/billing.utils.ts"),
                "export const usedHelper = () => 1;\nexport const deadHelper = () => 2;\n"
                    .to_string(),
            ),
            (
                PathBuf::from("src/app/orphan.service.ts"),
                "export class OrphanService {}\n".to_string(),
            ),
        ],
        Some(&[
            RuleId::UnusedFile,
            RuleId::UnusedExport,
            RuleId::UnusedDependency,
        ]),
    );
    let dead_rules: Vec<(RuleId, String)> = report_with_dead_code
        .diagnostics
        .iter()
        .map(|d| (d.rule, d.target_name.clone()))
        .collect();
    assert!(
        dead_rules.contains(&(RuleId::UnusedFile, "src/app/orphan.service.ts".to_string())),
        "Expected UnusedFile on src/app/orphan.service.ts, got: {dead_rules:#?}"
    );
    assert!(
        dead_rules.contains(&(RuleId::UnusedExport, "deadHelper".to_string())),
        "Expected UnusedExport on deadHelper, got: {dead_rules:#?}"
    );
    assert!(
        dead_rules.contains(&(
            RuleId::UnusedDependency,
            "unused-third-party-pkg".to_string()
        )),
        "Expected UnusedDependency on unused-third-party-pkg, got: {dead_rules:#?}"
    );
    assert_eq!(
        dead_rules.len(),
        3,
        "Expected only the 3 real dead-code findings, got: {dead_rules:#?}"
    );
}
