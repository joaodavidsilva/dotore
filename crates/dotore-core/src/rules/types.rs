//! Domain types for the unified rule registry, metadata, categories, tags,
//! **Capability Gate** predicates, **Contextual Owner** policies, **Prescription Tiers**,
//! and autofix patches.

mod diagnostics;

use serde::{Deserialize, Serialize};

use crate::config::CapabilityPredicate;

pub use self::diagnostics::*;

/// High-level category for a diagnostic rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleCategory {
    /// Correctness and runtime bug rules.
    Bugs,
    /// Re-render, CPU, network, and bundle performance rules.
    Performance,
    /// WCAG and UI accessibility rules.
    Accessibility,
    /// Security and trust-boundary rules.
    Security,
    /// Architecture, dead-code, and maintainability rules.
    Maintainability,
}

impl RuleCategory {
    /// Returns the canonical display name of this category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bugs => "Bugs",
            Self::Performance => "Performance",
            Self::Accessibility => "Accessibility",
            Self::Security => "Security",
            Self::Maintainability => "Maintainability",
        }
    }

    /// Parses a category name (case-insensitive).
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "bugs" | "correctness" => Some(Self::Bugs),
            "performance" | "perf" => Some(Self::Performance),
            "accessibility" | "a11y" => Some(Self::Accessibility),
            "security" => Some(Self::Security),
            "maintainability" | "architecture" | "arch" => Some(Self::Maintainability),
            _ => None,
        }
    }
}

/// Diagnostic severity level (`error` or `warning`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSeverity {
    /// Error-level finding (blocks CI by default).
    Error,
    /// Warning-level finding (advisory by default unless `--blocking warning` is set).
    Warning,
}

impl RuleSeverity {
    /// Returns `"error"` or `"warning"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

/// Severity override accepted in `dotore.config.*` and `package.json#dotore` (`"off"`, `"warn"`, `"error"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSeverityOverride {
    /// Promote or keep the rule at error severity.
    Error,
    /// Downgrade or enable the rule at warning severity.
    #[serde(alias = "warning")]
    Warn,
    /// Disable the rule completely.
    Off,
}

impl RuleSeverityOverride {
    /// Returns `"error"`, `"warn"`, or `"off"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Off => "off",
        }
    }

    /// Parses a severity override string (`"off"`, `"warn"`, `"warning"`, `"error"`).
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "off" | "none" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Behavioral tag attached to a rule in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleTag {
    /// Automatically suppressed in test and story files unless also tagged `MigrationHint`.
    TestNoise,
    /// UI design polish rule (opt-in during standard scans, active via `dotore design`).
    Design,
    /// API or version migration rule (still runs in test files even when tagged `TestNoise`).
    MigrationHint,
    /// Applies React JSX semantics and requires `Capability::React`.
    ReactJsxOnly,
    /// WebGL resource or rendering rule.
    Webgl,
    /// Three.js 3D engine rule.
    Three,
    /// React Three Fiber (`@react-three/fiber`) rule.
    R3f,
    /// React Native / Expo mobile rule.
    ReactNative,
    /// Security and trust-boundary scan rule.
    SecurityScan,
    /// Ink terminal UI rule.
    Ink,
    /// Server Action / Server Function boundary rule.
    ServerAction,
    /// Whole-project module graph / dead-code analysis rule.
    ProjectAnalysis,
    /// Opt-in rule (`default_enabled: false`).
    OptIn,
}

impl RuleTag {
    /// Returns the canonical kebab-case tag string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TestNoise => "test-noise",
            Self::Design => "design",
            Self::MigrationHint => "migration-hint",
            Self::ReactJsxOnly => "react-jsx-only",
            Self::Webgl => "webgl",
            Self::Three => "three",
            Self::R3f => "r3f",
            Self::ReactNative => "react-native",
            Self::SecurityScan => "security-scan",
            Self::Ink => "ink",
            Self::ServerAction => "server-action",
            Self::ProjectAnalysis => "project-analysis",
            Self::OptIn => "opt-in",
        }
    }

    /// Parses a [`RuleTag`] from its kebab-case string.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim() {
            "test-noise" => Some(Self::TestNoise),
            "design" => Some(Self::Design),
            "migration-hint" => Some(Self::MigrationHint),
            "react-jsx-only" => Some(Self::ReactJsxOnly),
            "webgl" => Some(Self::Webgl),
            "three" => Some(Self::Three),
            "r3f" => Some(Self::R3f),
            "react-native" => Some(Self::ReactNative),
            "security-scan" => Some(Self::SecurityScan),
            "ink" => Some(Self::Ink),
            "server-action" => Some(Self::ServerAction),
            "project-analysis" => Some(Self::ProjectAnalysis),
            "opt-in" => Some(Self::OptIn),
            _ => None,
        }
    }
}

/// **Contextual Owner** policy determining the syntax unit that owns a diagnostic during `--scope contextual` diff filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextualOwnerPolicy {
    /// Owned by the flagged source line(s).
    Line,
    /// Owned by the enclosing JSX element.
    JsxElement,
    /// Owned by the enclosing React **Subject** (component or custom hook) or function.
    Subject,
    /// Owned by explicit related AST nodes (such as a hook callback and its dependency array).
    RelatedNodes,
    /// Owned by the entire source file.
    File,
}

impl ContextualOwnerPolicy {
    /// Returns the kebab-case policy identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Line => "line",
            Self::JsxElement => "jsx-element",
            Self::Subject => "subject",
            Self::RelatedNodes => "related-nodes",
            Self::File => "file",
        }
    }
}

/// Level of intervention required to resolve a diagnostic (see `GLOSSARY.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrescriptionTier {
    /// Deterministic single- or cross-file rewrite applied directly by `dotore fix`.
    Autofix,
    /// Localized single-**Subject** change with a direct code recipe.
    Surgical,
    /// State-model or cross-**Subject** contract redesign.
    Refactor,
}

impl PrescriptionTier {
    /// Returns the kebab-case label for this tier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Autofix => "autofix",
            Self::Surgical => "surgical",
            Self::Refactor => "refactor",
        }
    }

    /// Parses a tier name from CLI filters.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim() {
            "autofix" => Some(Self::Autofix),
            "surgical" => Some(Self::Surgical),
            "refactor" => Some(Self::Refactor),
            _ => None,
        }
    }
}


/// Canonical identifier for each diagnostic rule in `dotore`.
#[rustfmt::skip]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleId {
    #[doc = "Updating state from props or state inside `useEffect`."] NoDerivedState, #[doc = "Chaining state updates across one or multiple `useEffect`s."] NoChainStateUpdates, #[doc = "Using state/props + `useEffect` as an event handler."] NoEventHandler,
    #[doc = "Adjusting partial state when a prop changes."] NoAdjustStateOnPropChange, #[doc = "Resetting all state when a prop changes instead of passing `key`."] NoResetAllStateOnPropChange, #[doc = "Calling a parent callback prop with live local state inside `useEffect`."] NoPassLiveStateToParent,
    #[doc = "Calling a parent callback prop with fetched/hook data inside `useEffect`."] NoPassDataToParent, #[doc = "Subscribing to an external store in `useEffect` instead of `useSyncExternalStore`."] NoExternalStoreSubscription, #[doc = "Initializing state synchronously in a mount-only `useEffect(..., [])`."] NoInitializeState,
    #[doc = "Fetching data inside `useEffect` (with or without cancellation cleanup)."] NoFetchInEffect, #[doc = "Missing `key` prop on elements in an array or iterator."] JsxKey, #[doc = "Using array index as `key` prop in `.map()`."] NoArrayIndexAsKey,
    #[doc = "Referencing an undefined JSX component identifier."] JsxNoUndef, #[doc = "Missing or unnecessary dependencies in React hooks (`useEffect`, `useMemo`, `useCallback`)."] ExhaustiveDeps, #[doc = "Exporting non-component values alongside React components in Fast Refresh modules."] OnlyExportComponents,
    #[doc = "Mutating `useState` value binding directly instead of calling the state setter."] NoDirectMutationState, #[doc = "Passing a freshly allocated object literal as a JSX prop (disabled when React Compiler is active)."] JsxNoNewObjectAsProp, #[doc = "`<img>` element missing accessible `alt` attribute."] AltText,
    #[doc = "Animation / motion usage without reduced-motion guard."] RequireReducedMotion, #[doc = "Vague button label (`\"Click here\"`, `\"Submit\"`) flagged in design audit."] DesignNoVagueButtonLabel, #[doc = "Using `dangerouslySetInnerHTML` on a JSX element."] NoDanger,
    #[doc = "`\"use server\"` action missing an authentication guard."] ServerAuthActions, #[doc = "`await` inside a `for`/`while` loop instead of `Promise.all`."] AsyncAwaitInLoop, #[doc = "Passing render-prop children function to a component (skipped on library entrypoints)."] NoRenderPropChildren,
    #[doc = "Unreferenced source file in the project module graph."] UnusedFile, #[doc = "Exported value symbol with no importer in the project module graph."] UnusedExport, #[doc = "Exported TypeScript type or interface with no importer in the project module graph."] UnusedType,
    #[doc = "Declared `dependencies` package in `package.json` with no discovered usage."] UnusedDependency, #[doc = "Declared `devDependencies` package in `package.json` with no discovered usage."] UnusedDevDependency, #[doc = "Runtime import cycle across modules in a strongly connected component."] CircularDependency,
    #[doc = "Structurally duplicated JSX subtree across components or files."] DuplicateJsxSubtree, #[doc = "Raw `<img>` element in Next.js instead of `next/image`."] NextjsNoImgElement, #[doc = "Raw text node outside `<Text>` or configured `textComponents` in React Native."] RnNoRawText,
    #[doc = "Dynamic `process.env[key]` access in Expo instead of static `process.env.EXPO_PUBLIC_*`."] ExpoNoNonInlinedEnv, #[doc = "`useQuery` with a `queryFn` that returns `undefined` / `void`."] QueryNoVoidQueryFn, #[doc = "TanStack Start `createServerFn` handler without `.validator(...)` input validation."] TanstackStartServerFnValidateInput,
    #[doc = "Allocating Three.js geometry inside `requestAnimationFrame`."] ThreeNoGeometryInFrameLoop, #[doc = "Unbounded device pixel ratio."] R3fCapDevicePixelRatio, #[doc = "Too many shadow-casting point lights."] R3fLimitShadowedPointLights,
    #[doc = "Clock advanced inside useFrame."] R3fNoAdvancingClockInUseFrame, #[doc = "Allocation inside an R3F pointer-move handler."] R3fNoAllocationInPointerMove, #[doc = "Async useFrame callback."] R3fNoAsyncUseFrame,
    #[doc = "Three.js clone inside useFrame."] R3fNoCloneInUseFrame, #[doc = "R3F shader precompilation inside useFrame."] R3fNoCompileInUseFrame, #[doc = "useThree selector reads a mutable Three.js field."] R3fNoDeepUseThreeSelector,
    #[doc = "Disposal of a cached R3F loader asset."] R3fNoDisposeLoaderCache, #[doc = "Primitive object mounted twice."] R3fNoDuplicatePrimitiveObject, #[doc = "R3F catalogue extension during render."] R3fNoExtendInRender,
    #[doc = "Whole Three.js namespace registered with R3F."] R3fNoExtendThreeNamespace, #[doc = "Fresh R3F portal container."] R3fNoFreshPortalContainer, #[doc = "Fresh useThree selector result."] R3fNoFreshUseThreeSelector,
    #[doc = "PBR prop ignored by R3F meshBasicMaterial."] R3fNoIgnoredBasicMaterialProperties, #[doc = "R3F GPU renderer ignores line width."] R3fNoIgnoredLinewidth, #[doc = "Imperative attachment of an R3F-managed ref."] R3fNoImperativeAttachOfManagedRef,
    #[doc = "Inline primitive object."] R3fNoInlinePrimitiveObject, #[doc = "Inline R3F resource prop."] R3fNoInlineResourceProp, #[doc = "Private R3F import."] R3fNoInternalImports,
    #[doc = "Manual resize loop for an R3F-owned renderer."] R3fNoManualCanvasResize, #[doc = "Mutation of a cached R3F loader asset."] R3fNoMutateLoaderCache, #[doc = "R3F uniform prop source mutated after being copied."] R3fNoMutateUniformPropSourceInUseFrame,
    #[doc = "Mutation of shared R3F pointer-event data."] R3fNoMutatingPointerEventData, #[doc = "Ignored normalization on R3F float attribute."] R3fNoNormalizedFloatBufferAttribute, #[doc = "Nullish R3F loader input."] R3fNoNullLoaderInput,
    #[doc = "Pointer capture called on an R3F scene object."] R3fNoObjectPointerCapture, #[doc = "Competing animation loop alongside useFrame."] R3fNoRecursiveRafWithUseFrame, #[doc = "R3F shader configuration mutates every frame."] R3fNoShaderConfigurationMutationInUseFrame,
    #[doc = "R3F light cannot cast shadows."] R3fNoShadowsOnUnsupportedLight, #[doc = "React state update inside an R3F pointer-move handler."] R3fNoStateInPointerMove, #[doc = "React state update inside useFrame."] R3fNoStateInUseFrame,
    #[doc = "Synchronous readback inside useFrame."] R3fNoSyncReadbackInUseFrame, #[doc = "Unstable R3F constructor args."] R3fNoUnstableArgs, #[doc = "Dependency array passed to useFrame."] R3fNoUseFrameDependencyArray,
    #[doc = "Per-instance CPU transform animation in R3F useFrame."] R3fPreferGpuInstancedAnimation, #[doc = "Per-vertex CPU animation in R3F useFrame."] R3fPreferGpuPositionAnimation, #[doc = "Repeated R3F meshes use separate draw calls."] R3fPreferInstancedMesh,
    #[doc = "Imperative Three.js loader in a React effect."] R3fPreferUseLoader, #[doc = "R3F animation mixer is never advanced."] R3fRequireAnimationMixerUpdate, #[doc = "R3F changed data texture is not marked for upload."] R3fRequireDataTextureUpdate,
    #[doc = "R3F per-frame buffer upload keeps static usage."] R3fRequireDynamicBufferUsage, #[doc = "Metal R3F material has no environment."] R3fRequireEnvironmentForMetal, #[doc = "Frame-rate-dependent animation."] R3fRequireFrameDelta,
    #[doc = "Unreleased global R3F render-loop effect."] R3fRequireGlobalEffectCleanup, #[doc = "Instanced mesh buffer is not marked for upload."] R3fRequireInstancedBufferUpdate, #[doc = "R3F PBR material has no lighting source."] R3fRequireLightingForPbr,
    #[doc = "Normal-mapped R3F geometry has no normals."] R3fRequireLitMaterialNormals, #[doc = "Locally owned Three.js texture is not disposed."] R3fRequireOwnedTextureCleanup, #[doc = "R3F position buffer is not marked for upload."] R3fRequirePositionBufferUpdate,
    #[doc = "Missing camera projection-matrix update."] R3fRequireProjectionMatrixUpdate, #[doc = "R3F renderer leaves an offscreen target bound."] R3fRequireRenderTargetReset, #[doc = "Positive useFrame priority without a render."] R3fRequireRenderWithPositivePriority,
    #[doc = "R3F root without unmount cleanup."] R3fRequireRootUnmount, #[doc = "R3F shadow caster without Canvas shadow maps."] R3fRequireShadowsEnabled, #[doc = "R3F material opacity is ignored."] R3fRequireTransparentForOpacity,
    #[doc = "Mapped R3F mesh geometry has no UVs."] R3fRequireUvForTextureMap, #[doc = "R3F texture repeat without repeat wrapping."] R3fTextureRepeatRequiresWrapping, #[doc = "R3F buffer attribute has a partial final item."] R3fValidBufferAttributeArrayLength,
    #[doc = "Invalid R3F buffer attribute item size."] R3fValidBufferAttributeItemSize, #[doc = "R3F fog has invalid range parameters."] R3fValidFogParameters, #[doc = "R3F material opacity outside its normalized range."] R3fValidMaterialOpacity,
    #[doc = "Invalid R3F orthographic camera."] R3fValidOrthographicCamera, #[doc = "R3F PBR material factor outside its normalized range."] R3fValidPbrMaterialProperties, #[doc = "Invalid R3F perspective camera."] R3fValidPerspectiveCamera,
    #[doc = "Invalid R3F physical material property."] R3fValidPhysicalMaterialProperties, #[doc = "Invalid R3F raycaster distance range."] R3fValidRaycasterRange, #[doc = "Invalid R3F shadow map size."] R3fValidShadowMapSize,
    #[doc = "Invalid R3F spotlight cone."] R3fValidSpotLightProperties, #[doc = "R3F texture has an incompatible color space."] R3fValidTextureColorSpace, #[doc = "Incompatible R3F Canvas renderer prop."] R3fWebgpuCanvasPropCompatibility,
    #[doc = "WebGPU root reads deprecated gl state."] R3fWebgpuNoGlState, #[doc = "R3F WebGPU high precision conflicts with instanced meshes."] R3fWebgpuNoHighPrecisionInstancing, #[doc = "JavaScript branch reads a TSL uniform value."] R3fWebgpuNoJsUniformBranch,
    #[doc = "Legacy EffectComposer inside an R3F WebGPU Canvas."] R3fWebgpuNoLegacyEffectComposer, #[doc = "Legacy shader material API inside an R3F WebGPU Canvas."] R3fWebgpuNoLegacyMaterialApi, #[doc = "Unregistered WebGPU pipeline pass."] R3fWebgpuNoUnregisteredPipelinePass,
    #[doc = "R3F WebGPU factory skips asynchronous initialization."] R3fWebgpuRequireAsyncInit, #[doc = "Unbounded Three.js device pixel ratio."] ThreeCapDevicePixelRatio, #[doc = "Postprocessing pass follows OutputPass."] ThreeEffectComposerOutputPassLast,
    #[doc = "EffectComposer size is stale after renderer resize."] ThreeEffectComposerRequireSizeOnResize, #[doc = "GPU computation initialization error is ignored."] ThreeGpuComputationHandleInitError, #[doc = "GPU computation runs before initialization."] ThreeGpuComputationRequireInitBeforeCompute,
    #[doc = "GPU computation variable has an invalid shader name."] ThreeGpuComputationValidVariableName, #[doc = "Too many shadow-casting Three.js point lights."] ThreeLimitShadowedPointLights, #[doc = "Three.js allocation inside pointer-move handler."] ThreeNoAllocationInPointerMove,
    #[doc = "Async Three.js animation callback."] ThreeNoAsyncAnimationLoop, #[doc = "Three.js clone inside animation loop."] ThreeNoCloneInAnimationLoop, #[doc = "Three.js shader precompilation inside animation loop."] ThreeNoCompileInAnimationLoop,
    #[doc = "PBR property ignored by Three.js MeshBasicMaterial."] ThreeNoIgnoredBasicMaterialProperties, #[doc = "Three.js GPU renderer ignores line width."] ThreeNoIgnoredLinewidth, #[doc = "Material recompiled inside animation loop."] ThreeNoMaterialRecompileInAnimationLoop,
    #[doc = "Allocation inside Three.js animation loop."] ThreeNoNewInAnimationLoop, #[doc = "Ignored normalization on Three.js float attribute."] ThreeNoNormalizedFloatBufferAttribute, #[doc = "Three.js object constructed during React render."] ThreeNoObjectConstructionInRender,
    #[doc = "Redundant uniformsNeedUpdate inside animation loop."] ThreeNoRedundantUniformsNeedUpdate, #[doc = "Shader configuration mutates every animation frame."] ThreeNoShaderConfigurationMutationInAnimationLoop, #[doc = "Three.js light cannot cast shadows."] ThreeNoShadowsOnUnsupportedLight,
    #[doc = "React state update inside Three.js animation loop."] ThreeNoStateInAnimationLoop, #[doc = "React state update inside Three.js pointer-move handler."] ThreeNoStateInPointerMove, #[doc = "Synchronous GPU readback in Three.js loop."] ThreeNoSyncReadbackInAnimationLoop,
    #[doc = "Renderer resized unconditionally every frame."] ThreeNoUnconditionalRendererResizeInAnimationLoop, #[doc = "onBeforeCompile variant lacks a program cache key."] ThreeOnBeforeCompileRequireProgramCacheKey, #[doc = "Per-instance CPU transform animation in a Three.js loop."] ThreePreferGpuInstancedAnimation,
    #[doc = "Per-vertex CPU animation in a Three.js frame loop."] ThreePreferGpuPositionAnimation, #[doc = "Repeated Three.js meshes use separate draw calls."] ThreePreferInstancedMesh, #[doc = "Three.js renderer uses manual animation frames."] ThreePreferSetAnimationLoop,
    #[doc = "Raw fragment shader lacks float precision."] ThreeRawShaderRequireFragmentFloatPrecision, #[doc = "Raw shader uses GLSL 3 syntax without GLSL3."] ThreeRawShaderRequireGlsl3Version, #[doc = "Unreleased Three.js animation mixer actions."] ThreeRequireAnimationMixerCleanup,
    #[doc = "Three.js animation mixer is never advanced."] ThreeRequireAnimationMixerUpdate, #[doc = "Three.js resize leaves camera aspect stale."] ThreeRequireCameraAspectOnResize, #[doc = "Undisposed imperative Three.js controls."] ThreeRequireControlsCleanup,
    #[doc = "Three.js controls require per-frame updates."] ThreeRequireControlsUpdate, #[doc = "Changed data texture is not marked for upload."] ThreeRequireDataTextureUpdate, #[doc = "Per-frame buffer upload keeps static usage."] ThreeRequireDynamicBufferUsage,
    #[doc = "Metal Three.js material has no environment."] ThreeRequireEnvironmentForMetal, #[doc = "Frame-rate-dependent Three.js animation."] ThreeRequireFrameDelta, #[doc = "Undisposed Three.js GPU computation renderer."] ThreeRequireGpuComputationCleanup,
    #[doc = "Three.js instanced mesh buffer is not marked for upload."] ThreeRequireInstancedBufferUpdate, #[doc = "KTX2Loader used before renderer support detection."] ThreeRequireKtx2DetectSupport, #[doc = "Three.js PBR material has no lighting source."] ThreeRequireLightingForPbr,
    #[doc = "Normal-mapped Three.js geometry has no normals."] ThreeRequireLitMaterialNormals, #[doc = "Three.js asset load has no local error path."] ThreeRequireLoaderErrorHandling, #[doc = "Locally owned Three.js geometry is not disposed."] ThreeRequireOwnedGeometryCleanup,
    #[doc = "Locally owned Three.js material is not disposed."] ThreeRequireOwnedMaterialCleanup, #[doc = "Locally owned Three.js texture is not disposed."] ThreeRequireOwnedTextureCleanup, #[doc = "Three.js position buffer is not marked for upload."] ThreeRequirePositionBufferUpdate,
    #[doc = "Undisposed Three.js postprocessing resource."] ThreeRequirePostprocessingCleanup, #[doc = "Missing Three.js camera projection-matrix update."] ThreeRequireProjectionMatrixUpdate, #[doc = "Three.js animation loop never renders."] ThreeRequireRenderInAnimationLoop,
    #[doc = "Undisposed Three.js render target."] ThreeRequireRenderTargetCleanup, #[doc = "Three.js renderer leaves an offscreen target bound."] ThreeRequireRenderTargetReset, #[doc = "Undisposed Three.js renderer."] ThreeRequireRendererCleanup,
    #[doc = "Three.js renderer canvas is never attached to the DOM."] ThreeRequireRendererDomAttachment, #[doc = "Three.js renderer drawing buffer is never sized."] ThreeRequireRendererSize, #[doc = "Three.js shadow caster without renderer shadow maps."] ThreeRequireShadowsEnabled,
    #[doc = "Three.js texture wrapping changes without re-upload."] ThreeRequireTextureUpdateAfterWrappingChange, #[doc = "Three.js material opacity is ignored."] ThreeRequireTransparentForOpacity, #[doc = "Mapped Three.js mesh geometry has no UVs."] ThreeRequireUvForTextureMap,
    #[doc = "Undisposed Three.js worker-backed loader."] ThreeRequireWorkerLoaderCleanup, #[doc = "Shader uses a constant out-of-bounds index."] ThreeShaderNoConstantOutOfBoundsIndex, #[doc = "Shader derivative runs in non-uniform control flow."] ThreeShaderNoDerivativesInNonuniformFlow,
    #[doc = "GLSL 3 shader uses an unavailable GLSL 1 symbol."] ThreeShaderNoGlsl1SyntaxWithGlsl3, #[doc = "Shader uses invalid clamp bounds."] ThreeShaderNoInvalidClampBounds, #[doc = "Shader uses invalid constant bit operations."] ThreeShaderNoInvalidConstantBitOperations,
    #[doc = "Shader uses invalid constant math."] ThreeShaderNoInvalidConstantMath, #[doc = "Shader uses invalid smoothstep edges."] ThreeShaderNoInvalidSmoothstepEdges, #[doc = "Shader inverts a uniform matrix per invocation."] ThreeShaderNoInverseOfUniform,
    #[doc = "ShaderMaterial redeclares a Three.js builtin."] ThreeShaderNoRedeclaredBuiltins, #[doc = "Shader redundantly writes fragment depth."] ThreeShaderNoRedundantFragDepth, #[doc = "Shader declares a reserved GLSL identifier."] ThreeShaderNoReservedIdentifiers,
    #[doc = "Three shader source contains a version directive."] ThreeShaderNoVersionDirective, #[doc = "Shader uses pow for a small integer exponent."] ThreeShaderPreferSmallIntegerPow, #[doc = "Shader compares a computed distance."] ThreeShaderPreferSquaredDistanceComparison,
    #[doc = "Shader uniform value has an incompatible JavaScript shape."] ThreeShaderRequireCompatibleUniformValues, #[doc = "Fragment shader leaves a color output undefined."] ThreeShaderRequireFragmentOutputOnAllPaths, #[doc = "Shader stages declare incompatible uniforms."] ThreeShaderRequireMatchingUniforms,
    #[doc = "Shader stage interface does not match."] ThreeShaderRequireMatchingVaryings, #[doc = "Vertex shader leaves gl_Position undefined."] ThreeShaderRequirePositionOnAllPaths, #[doc = "Shader uniform has no material binding."] ThreeShaderRequireUniformBindings,
    #[doc = "Shader global has an invalid initializer."] ThreeShaderValidGlobalInitializers, #[doc = "Shader uniform has an invalid JavaScript definition."] ThreeShaderValidUniformDefinitions, #[doc = "Three.js texture repeat without repeat wrapping."] ThreeTextureRepeatRequiresWrapping,
    #[doc = "JavaScript branch reads a TSL uniform value."] ThreeTslNoJsUniformBranch, #[doc = "Buffer attribute has a partial final item."] ThreeValidBufferAttributeArrayLength, #[doc = "Invalid Three.js buffer attribute item size."] ThreeValidBufferAttributeItemSize,
    #[doc = "Data texture storage is too short."] ThreeValidDataTextureDataLength, #[doc = "Data texture has an invalid dimension."] ThreeValidDataTextureDimensions, #[doc = "Three.js fog has invalid range parameters."] ThreeValidFogParameters,
    #[doc = "GPU computation has an invalid texture dimension."] ThreeValidGpuComputationDimensions, #[doc = "Three.js material opacity outside its normalized range."] ThreeValidMaterialOpacity, #[doc = "Invalid Three.js orthographic camera."] ThreeValidOrthographicCamera,
    #[doc = "Three.js PBR material factor outside its normalized range."] ThreeValidPbrMaterialProperties, #[doc = "Invalid Three.js perspective camera."] ThreeValidPerspectiveCamera, #[doc = "Invalid Three.js physical material property."] ThreeValidPhysicalMaterialProperties,
    #[doc = "Invalid Three.js raycaster distance range."] ThreeValidRaycasterRange, #[doc = "Invalid Three.js shadow map size."] ThreeValidShadowMapSize, #[doc = "Invalid Three.js spotlight cone."] ThreeValidSpotLightProperties,
    #[doc = "Three.js texture has an incompatible color space."] ThreeValidTextureColorSpace, #[doc = "WebGPU high precision conflicts with instanced meshes."] ThreeWebgpuNoHighPrecisionInstancing, #[doc = "Legacy EffectComposer used with WebGPURenderer."] ThreeWebgpuNoLegacyEffectComposer,
    #[doc = "Legacy material API used with WebGPURenderer."] ThreeWebgpuNoLegacyMaterialApi, #[doc = "WebGPU renderer used before asynchronous initialization."] ThreeWebgpuRequireInitBeforeSyncOperation, #[doc = "Synchronous GPU readback inside animation loop."] WebglNoSyncReadbackInAnimationLoop,
    #[doc = "Allocating `new THREE.*` objects inside React Three Fiber `useFrame`."] R3fNoNewInUseFrame, #[doc = "Calling a Zustand store hook without a selector (`useStore()`)."] ZustandNoWholeStoreDestructure, #[doc = "Calling Jotai `selectAtom` inline inside a component render body."] JotaiSelectAtomInRenderBody,
    #[doc = "Calling MobX `reaction` / `autorun` inside `useEffect` without returning its disposer."] MobxReactionDisposerDiscarded, #[doc = "Reading a Valtio `useSnapshot` result inside an event handler callback instead of the proxy."] ValtioNoSnapshotInCallback, #[doc = "Importing from `'react'` in a pure Preact project."] PreactNoReactImport,
    #[doc = "Raw text outside Ink `<Text>` in terminal UI components."] InkNoRawText, #[doc = "Deprecated Zod v4 `.strict()` / `.passthrough()` / `.strip()` schema calls."] ZodV4DeprecatedParse, #[doc = "Ambiguous link text."] AnchorAmbiguousText,
    #[doc = "Anchor has no content."] AnchorHasContent, #[doc = "Anchor used as a button."] AnchorIsValid, #[doc = "Fragment link target is missing."] AnchorTargetExists,
    #[doc = "aria-activedescendant missing tabindex."] AriaActivedescendantHasTabindex, #[doc = "Braille-only accessible description."] AriaBrailleEquivalent, #[doc = "Invalid ARIA attribute."] AriaProps,
    #[doc = "Invalid ARIA attribute value."] AriaProptypes, #[doc = "Invalid ARIA role."] AriaRole, #[doc = "ARIA on unsupported element."] AriaUnsupportedElements,
    #[doc = "Invalid autocomplete value."] AutocompleteValid, #[doc = "Base UI dialog popup without a title."] BaseUiDialogPopupRequiresTitle, #[doc = "Base UI field control without a label."] BaseUiFieldRequiresLabel,
    #[doc = "Click handler missing keyboard handler."] ClickEventsHaveKeyEvents, #[doc = "Control missing accessible label."] ControlHasAssociatedLabel, #[doc = "Data table has no accessible name."] DataTableRequiresAccessibleName,
    #[doc = "Em dash in JSX text."] DesignNoEmDashInJsxText, #[doc = "Redundant padding axes."] DesignNoRedundantPaddingAxes, #[doc = "Redundant width and height axes."] DesignNoRedundantSizeAxes,
    #[doc = "space-* utility on flex children."] DesignNoSpaceOnFlexChildren, #[doc = "Three dots instead of ellipsis."] DesignNoThreePeriodEllipsis, #[doc = "Details disclosure has no explicit summary."] DetailsRequiresSummary,
    #[doc = "Dialog without accessible name."] DialogHasAccessibleName, #[doc = "Table header has no accessible text."] EmptyTableHeader, #[doc = "Fieldset group has no legend."] FieldsetRequiresLegend,
    #[doc = "Form control is omitted from named submission data."] FormControlRequiresName, #[doc = "Heading has no content."] HeadingHasContent, #[doc = "html element missing lang."] HtmlHasLang,
    #[doc = "Interactive control contains another focusable control."] HtmlNoNestedInteractive, #[doc = "Conflicting document language declarations."] HtmlXmlLangMismatch, #[doc = "iframe missing title."] IframeHasTitle,
    #[doc = "Frame title is duplicated."] IframeTitleUnique, #[doc = "Redundant words in image alt."] ImgRedundantAlt, #[doc = "Invalid Ink accessibility semantics."] InkValidAriaSemantics,
    #[doc = "Interactive element not focusable."] InteractiveSupportsFocus, #[doc = "Label missing associated control."] LabelHasAssociatedControl, #[doc = "Invalid lang attribute value."] Lang,
    #[doc = "Loading state removes its initiating action."] LoadingActionPreservesTrigger, #[doc = "Media missing captions."] MediaHasCaption, #[doc = "Mouse handler missing focus handler."] MouseEventsHaveKeyEvents,
    #[doc = "accessKey attribute used."] NoAccessKey, #[doc = "Long body copy is set in all caps."] NoAllCapsBodyText, #[doc = "Pixel arbitrary font size."] NoArbitraryPxFontSize,
    #[doc = "Document body hidden from assistive technology."] NoAriaHiddenOnBody, #[doc = "aria-hidden on focusable element."] NoAriaHiddenOnFocusable, #[doc = "Invalid control has no error description."] NoAriaInvalidWithoutDescription,
    #[doc = "Status live region interrupts assistive technology."] NoAssertiveStatus, #[doc = "Content auto-scrolls forever."] NoAutoScrollingContent, #[doc = "Autofocus on an element."] NoAutofocus,
    #[doc = "Autoplaying media without muted."] NoAutoplayWithoutMuted, #[doc = "Paste blocked in an authentication field."] NoBlockedPaste, #[doc = "Image has no usable source."] NoBrokenImageSource,
    #[doc = "Overlay can be clipped by an overflow container."] NoClippedOverlay, #[doc = "Page root uses a generic default font choice."] NoCommonRootFont, #[doc = "Controlled selection change steals focus."] NoControlledSelectionFocusEffect,
    #[doc = "Bounded text container has cramped padding."] NoCrampedContainerPadding, #[doc = "Letter spacing compresses text excessively."] NoCrushedLetterSpacing, #[doc = "Colored glow on dark background."] NoDarkModeGlow,
    #[doc = "Empty blurred color orb decorates the layout."] NoDecorativeBlurOrb, #[doc = "Surface draws a decorative grid background."] NoDecorativeGridBackground, #[doc = "Stable copy pulses for attention."] NoDecorativePulse,
    #[doc = "Large decorative radial spotlight."] NoDecorativeRadialSpotlight, #[doc = "Page root uses a default purple-spectrum gradient."] NoDefaultPurplePageGradient, #[doc = "Page defaults to a warm off-white surface."] NoDefaultWarmPageSurface,
    #[doc = "Deprecated Tailwind v4 utility."] NoDeprecatedTailwindClass, #[doc = "Zoom disabled on viewport."] NoDisabledZoom, #[doc = "Distracting marquee or blink element."] NoDistractingElements,
    #[doc = "Referenced ID is duplicated."] NoDuplicateStaticIdReference, #[doc = "Tailwind utility is assembled dynamically."] NoDynamicTailwindClassFragment, #[doc = "UI motion starts with ease-in."] NoEaseInMotion,
    #[doc = "Heading uses emoji as decoration."] NoEmojiHeadingDecoration, #[doc = "Empty semantic element renders as a card."] NoEmptyCardShell, #[doc = "Page boxes too many groups into cards."] NoExcessiveCardSurfaces,
    #[doc = "Page centers multiple body-copy blocks."] NoExcessiveCenteredCopy, #[doc = "Page mixes too many font families."] NoExcessiveFontFamilies, #[doc = "Motion child stagger is too long."] NoExcessiveMotionStagger,
    #[doc = "Page overuses pill-shaped treatments."] NoExcessivePillTreatment, #[doc = "Preview redraws decorative browser chrome."] NoFakeBrowserChrome, #[doc = "Fixed element is scoped by a transformed ancestor."] NoFixedInsideTransformedAncestor,
    #[doc = "Page typography uses a compressed size range."] NoFlatPageTypeScale, #[doc = "Focus waits for animation completion."] NoFocusInAnimationCompletionHandler, #[doc = "aria-hidden subtree contains focusable content."] NoFocusableContentInAriaHidden,
    #[doc = "Focusable control inside role=text."] NoFocusableContentInRoleText, #[doc = "Hero uses a full-viewport centered template."] NoFullViewportCenteredHero, #[doc = "Full viewport width causes overflow."] NoFullViewportWidth,
    #[doc = "Page uses generic marketing language."] NoGenericMarketingCopy, #[doc = "Compact icon tile uses a generic purple-to-blue gradient."] NoGenericPurpleBlueIconGradient, #[doc = "Gradient text is hard to read."] NoGradientText,
    #[doc = "Gray text on colored background."] NoGrayOnColoredBackground, #[doc = "Hairline border is paired with a diffuse shadow."] NoHairlineBorderWideShadow, #[doc = "Hero uses a decorative eyebrow label."] NoHeroEyebrowChip,
    #[doc = "Content is revealed only on hover."] NoHoverOnlyReveal, #[doc = "Card stacks an icon tile above its heading."] NoIconTileHeadingStack, #[doc = "Image scales or rotates on hover."] NoImageHoverTransform,
    #[doc = "Image has no reserved layout space."] NoImgWithoutDimensions, #[doc = "Pointer cursor has no interaction."] NoInertPointerAffordance, #[doc = "Sticky positioning has no inset."] NoInertStickyPosition,
    #[doc = "Bouncy easing animation."] NoInlineBounceEasing, #[doc = "Large inline style object rebuilds every render."] NoInlineExhaustiveStyle, #[doc = "Interactive element given noninteractive role."] NoInteractiveElementToNoninteractiveRole,
    #[doc = "Progress value falls outside its range."] NoInvalidProgressRange, #[doc = "Invisible native control lacks keyboard focus treatment."] NoInvisibleFocusControl, #[doc = "Display heading combines italic serif styling."] NoItalicSerifDisplayHeading,
    #[doc = "Justified text without hyphens."] NoJustifiedText, #[doc = "Interaction state changes layout geometry."] NoLayoutShiftingInteractionState, #[doc = "Animating layout properties."] NoLayoutTransitionInline,
    #[doc = "Transition duration too long."] NoLongTransitionDuration, #[doc = "Low-contrast text in inline style."] NoLowContrastInlineStyle, #[doc = "Page repeatedly uses manufactured contrast copy."] NoManufacturedContrastCopy,
    #[doc = "CSS and Motion animate the same property."] NoMixedAnimationOwners, #[doc = "File mixes visual icon families."] NoMixedIconLibraries, #[doc = "Page repeats one spacing value throughout."] NoMonotonousPageSpacing,
    #[doc = "View contains multiple main landmarks."] NoMultipleMainLandmarks, #[doc = "Repeated navigation landmarks need unique names."] NoMultipleUnlabeledNavigationLandmarks, #[doc = "Card surface is nested inside another card."] NoNestedCardSurface,
    #[doc = "Handler on non-interactive element."] NoNoninteractiveElementInteractions, #[doc = "Noninteractive element given interactive role."] NoNoninteractiveElementToInteractiveRole, #[doc = "Tabindex on non-interactive element."] NoNoninteractiveTabindex,
    #[doc = "Textarea resizing is disabled."] NoNonresizableTextarea, #[doc = "Styled numbers are used as section decoration."] NoNumberedSectionMarkers, #[doc = "outline:none removes focus ring."] NoOutlineNone,
    #[doc = "Hover state stacks too many effects."] NoOverloadedHoverState, #[doc = "Long headline uses an oversized display scale."] NoOversizedLongHeading, #[doc = "Text measure is too wide."] NoOverwideTextMeasure,
    #[doc = "Navigation count uses a pill badge."] NoPillNavigationCount, #[doc = "Field relies on placeholder text for its label."] NoPlaceholderOnlyField, #[doc = "Page renders a placeholder persona."] NoPlaceholderPersonaCopy,
    #[doc = "Enabled control ignores pointer input."] NoPointerDisabledEnabledControl, #[doc = "Presentational element exposes conflicting semantics."] NoPresentationRoleConflict, #[doc = "Decorative status dot pulses continuously."] NoPulsingStatusDot,
    #[doc = "Pure black background."] NoPureBlackBackground, #[doc = "Surface uses a pure-black shadow."] NoPureBlackShadow, #[doc = "Saturated radial halo on a dark surface."] NoRadialHalo,
    #[doc = "Reduced motion removes meaningful content."] NoReducedMotionContentRemoval, #[doc = "Redundant display utility."] NoRedundantDisplayClass, #[doc = "Redundant ARIA role."] NoRedundantRoles,
    #[doc = "Title tooltip repeats visible control text."] NoRedundantTitleTooltip, #[doc = "A card repeats the same text in distinct slots."] NoRepeatedContainerText, #[doc = "Page repeats boxed emoji as feature icons."] NoRepeatedEmojiTiles,
    #[doc = "Page repeats glass panels."] NoRepeatedGlassSurfaces, #[doc = "Hover scaling repeats across the page."] NoRepeatedHoverScale, #[doc = "Repeated tracked labels scaffold multiple sections."] NoRepeatedKickerLabels,
    #[doc = "Navigation repeats placeholder destinations."] NoRepeatedPlaceholderNavigation, #[doc = "Page repeats the same padded section shell."] NoRepeatedSectionShells, #[doc = "Surface uses a repeating gradient texture."] NoRepeatingGradientDecoration,
    #[doc = "Responsive styles hide a control's accessible name."] NoResponsiveHiddenAccessibleName, #[doc = "Server-side image map."] NoServerSideImageMap, #[doc = "Large illustration is assembled from primitive shapes."] NoShapeAssembledIllustration,
    #[doc = "Thick one-sided stripe."] NoSideTabBorder, #[doc = "Heading hierarchy skips a level."] NoSkippedHeadingLevel, #[doc = "Form control text is smaller than 16px."] NoSmallFormControlText,
    #[doc = "Smooth scrolling ignores reduced motion."] NoSmoothScrollWithoutReducedMotion, #[doc = "Interaction on static element."] NoStaticElementInteractions, #[doc = "MotionConfig always ignores reduced motion."] NoStaticMotionConfigNever,
    #[doc = "currentColor fights a fill/stroke class."] NoSvgCurrentcolorWithFillClass, #[doc = "Text button uses symmetric padding."] NoSymmetricTextButtonPadding, #[doc = "Animating a layout property."] NoTailwindLayoutTransition,
    #[doc = "Long all-caps heading has collision-prone leading."] NoTightAllCapsHeading, #[doc = "Body copy has cramped line spacing."] NoTightBodyLeading, #[doc = "Display heading uses the tightest tracking preset."] NoTightDisplayTracking,
    #[doc = "Text is too small."] NoTinyText, #[doc = "Tiny label combines uppercase text and decorative tracking."] NoTinyUppercaseTrackedLabel, #[doc = "Composite widget state feedback is delayed."] NoTransitionedCompositeWidgetState,
    #[doc = "Focus indicator animates into view."] NoTransitionedFocusRing, #[doc = "Icon button target is smaller than 24px."] NoUndersizedIconButton, #[doc = "Tailwind animation ignores reduced motion."] NoUngatedTailwindAnimation,
    #[doc = "Feature grid repeats one card recipe."] NoUniformFeatureCardGrid, #[doc = "Uninformative aria-label."] NoUninformativeAriaLabel, #[doc = "Short label uses uppercase monospace styling."] NoUppercaseMonoLabel,
    #[doc = "Navigation label uses uppercase tracking."] NoUppercaseTrackedNavigationLabel, #[doc = "Wide letter spacing on body text."] NoWideLetterSpacing, #[doc = "Excessively high z-index."] NoZIndex9999,
    #[doc = "Use dvh instead of vh for full height."] PreferDvhOverVh, #[doc = "Custom modal instead of dialog."] PreferHtmlDialog, #[doc = "Motion individual transforms miss compositor acceleration."] PreferMotionTransformProperty,
    #[doc = "Changing table numbers use proportional figures."] PreferTabularNumericData, #[doc = "Role used instead of HTML tag."] PreferTagOverRole, #[doc = "Use truncate shorthand."] PreferTruncateShorthand,
    #[doc = "Radio input missing name."] RadioInputMissingName, #[doc = "Radix dialog content without a title."] RadixDialogContentRequiresTitle, #[doc = "React Aria dialog without a heading."] ReactAriaDialogRequiresHeading,
    #[doc = "Autoplay video has no poster frame."] RequireAutoplayVideoPoster, #[doc = "Scaled menu omits its transform origin."] RequireScaleRevealTransformOrigin, #[doc = "ARIA button handles only one activation key."] RoleButtonRequiresCompleteKeyboardActivation,
    #[doc = "Role missing required ARIA props."] RoleHasRequiredAriaProps, #[doc = "Unsupported ARIA prop for role."] RoleSupportsAriaProps, #[doc = "scope attribute on non-th element."] Scope,
    #[doc = "Dialog content without a title."] ShadcnDialogContentRequiresTitle, #[doc = "FormItem control without a label."] ShadcnFormItemRequiresLabel, #[doc = "Icon-only Button without accessible name."] ShadcnIconButtonRequiresLabel,
    #[doc = "Duplicate CSS property in styled block."] StyledComponentsDuplicateCssPropertyInBlock, #[doc = "Positive tabindex value."] TabindexNoPositive, #[doc = "Defaulted empty `{}` or `[]` prop breaks `React.memo` or hook dependency stability."] RerenderMemoWithDefaultValue,
    #[doc = "`useMemo` building JSX before an early return that ignores it."] RerenderMemoBeforeEarlyReturn, #[doc = "Continuous hook value (`useWindowWidth`, `useScrollPosition`) used only for a threshold boolean."] RerenderDerivedStateFromHook, #[doc = "Calling `setState` on every high-frequency DOM event (`scroll`, `mousemove`, `wheel`) without transition/throttle."] RerenderTransitionsScroll,
    #[doc = "Calling `matchMedia()` inside a `useState` initializer."] NoMatchMediaInStateInitializer, #[doc = "Using `transition: all` or `transition-all` which animates layout properties."] NoTransitionAll, #[doc = "Animating layout-triggering CSS properties (`width`, `height`, `top`, `left`, `margin`, `padding`)."] NoLayoutPropertyAnimation,
    #[doc = "Passing an inline object, array, function, or JSX prop to a `memo()`-wrapped component."] NoInlinePropOnMemoComponent, #[doc = "`await` before an early-return guard that does not depend on the awaited value."] AsyncDeferAwait, #[doc = "Passing a local unmemoized object/array/function binding as `Context.Provider` `value`."] ContextProviderValueFromUnmemoizedLocalLiteral,
    #[doc = "Wrapping a trivially cheap expression in `useMemo`."] NoUsememoSimpleExpression, #[doc = "Using an inline `[]` or `{}` as a `||` / `??` fallback prop on a memoized component."] PreferStableEmptyFallback, #[doc = "Constructing a non-trivial `new X()` eagerly inside `useState(new X())`."] NoEagerNewInUseStateInitializer,
    #[doc = "Keeping `will-change` permanently active in JSX `className` or `style`."] NoPermanentWillChange, #[doc = "Recursive `requestAnimationFrame` callback with no stop condition and discarded request ID."] NoUnboundedAnimationFrameLoop, #[doc = "Unthrottled DOM style or animation mutation inside a `scroll` listener."] NoUnthrottledScrollMutation,
    #[doc = "Responsive `<img srcSet=\"...\">` with width descriptors missing `sizes`."] NoSrcsetWithoutSizes, #[doc = "`<img loading=\"lazy\" fetchPriority=\"high\">` with contradictory loading hints."] NoImgLazyWithHighFetchpriority, #[doc = "Static JSX element assigned to a `const` inside a component body instead of module scope."] RenderingHoistJsx,
    #[doc = "`<script src=\"...\">` without `defer` or `async`."] RenderingScriptDeferAsync, #[doc = "Nondeterministic time or random call (`new Date()`, `Date.now()`, `Math.random()`) rendered in JSX."] RenderingHydrationMismatchTime, #[doc = "Mount-only `useEffect` state synchronization causing post-paint hydration flash."] RenderingHydrationNoFlicker,
    #[doc = "Rendering different JSX branches on server vs. client by branching on browser globals."] NoHydrationBranchOnBrowserGlobal, #[doc = "Reading unguarded browser globals (`window`, `document`, `localStorage`, `navigator`) during render or hook init."] NoUnguardedBrowserGlobalInRenderOrHookInit, #[doc = "Locale- or timezone-dependent formatting during SSR render without explicit locale/timeZone."] NoLocaleFormatInRender,
    #[doc = "Calling `motionValue()` directly during React render instead of `useMotionValue()`."] MotionValueConstructorInRender, #[doc = "Mixing spring physics options (`stiffness`/`damping`/`mass`) with `duration`/`bounce`."] NoConflictingSpringOptions, #[doc = "Mutating a CSS custom property on `document.documentElement` or `document.body` inside an animation loop."] NoGlobalCssVariableAnimation,
    #[doc = "Animating a `blur(...)` filter exceeding 10px radius."] NoLargeAnimatedBlur, #[doc = "Using `React.lazy` on a React Router route `Component`/`element` instead of route `lazy`."] ReactRouterPreferRouteLazy, #[doc = "Sequential independent `fetch` awaits inside a React Router `loader`/`clientLoader`."] ReactRouterLoaderParallelFetch,
    #[doc = "`fetch()` inside a React Router `loader`/`clientLoader` that does not forward `request.signal`."] ReactRouterLoaderFetchForwardsSignal, #[doc = "Retired rule: `no-scale-from-zero`."] NoScaleFromZero, #[doc = "Retired rule: `rendering-animate-svg-wrapper`."] RenderingAnimateSvgWrapper,
    #[doc = "Retired rule: `rendering-usetransition-loading`."] RenderingUsetransitionLoading, #[doc = "Sequential independent `await` statements that can run concurrently via `Promise.all()`."] AsyncParallel, #[doc = "Spreading the accumulator inside `.reduce()` / `.reduceRight()` causing $O(n^2)$ copying."] NoSpreadAccumulatorInReduce,
    #[doc = "Deep-cloning with `JSON.parse(JSON.stringify(x))` instead of `structuredClone(x)`."] NoJsonParseStringifyClone, #[doc = "Synchronous `XMLHttpRequest.open(method, url, false)` blocking the main thread."] NoSyncXhr, #[doc = "Calling `document.write()` or `document.writeln()`."] NoDocumentWrite,
    #[doc = "Calling `URL.createObjectURL()` without a matching `URL.revokeObjectURL()`."] NoCreateObjectUrlWithoutRevoke, #[doc = "Chained `.map()` / `.filter()` array iterations that traverse the list multiple times."] JsCombineIterations, #[doc = "Repeated `Array.includes()` / `Array.indexOf()` lookups inside a loop instead of `Set`/`Map`."] JsSetMapLookups,
    #[doc = "Constructing `new RegExp()` with a static pattern inside a loop."] JsHoistRegexp, #[doc = "Constructing `new Intl.*()` inside a function or render body without caching/memoization."] JsHoistIntl, #[doc = "Chained `.map().filter(Boolean)` traversing the array twice."] JsFlatmapFilter,
    #[doc = "Sorting an array with `.sort()` only to read its minimum or maximum element."] JsMinMaxLoop, #[doc = "Comparing two arrays with `.every()` without checking `.length` equality first."] JsLengthCheckFirst, #[doc = "Calling `array.find()` / `array.findIndex()` with an equality predicate inside a loop."] JsIndexMaps,
    #[doc = "Reading the same `localStorage` / `sessionStorage` key multiple times in one function."] JsCacheStorage, #[doc = "Reading the same deep property chain (`a.b.c`) 3+ times inside a loop."] JsCachePropertyAccess, #[doc = "Interleaving multiple DOM `.style` writes with layout reads inside a loop."] JsBatchDomCss,
    #[doc = "Async `.reduce()` callback that does not `await` its accumulator parameter."] JsAsyncReduceWithoutAwaitedAcc, #[doc = "Retired rule: `js-tosorted-immutable`."] JsTosortedImmutable, #[doc = "Retired rule: `js-early-exit`."] JsEarlyExit,
    #[doc = "Registering `wheel`, `mousewheel`, `touchstart`, or `touchmove` listener without `{ passive: true }`."] ClientPassiveEventListeners, #[doc = "Retired rule: `client-localstorage-no-version`."] ClientLocalstorageNoVersion, #[doc = "Importing and calling `flushSync` from `react-dom`, skipping View Transitions and concurrent rendering."] NoFlushSync,
    #[doc = "Calling `document.startViewTransition()` directly in a file that imports React's `<ViewTransition>`."] NoDocumentStartViewTransition, #[doc = "Importing from a barrel (`index.ts`) file instead of the direct source module."] NoBarrelImport, #[doc = "Importing from the full `'lodash'` bundle instead of `'lodash/<fn>'` subpaths."] NoFullLodashImport,
    #[doc = "Importing `'moment'` instead of lightweight alternatives (`date-fns`, `dayjs`)."] NoMoment, #[doc = "Eagerly importing a heavy library (`monaco-editor`, `recharts`, `chart.js`, `mermaid`, etc.)."] PreferDynamicImport, #[doc = "Non-static dynamic `import(expr)` or `require(expr)` that prevents bundler code-splitting."] NoDynamicImportPath,
    #[doc = "External third-party `<script src=\"https://...\">` without `defer` or `async`."] NoUndeferredThirdParty, #[doc = "Importing full `motion` from `framer-motion` / `motion/react` instead of `LazyMotion` + `m`."] UseLazyMotion, #[doc = "Using both `children` and `dangerouslySetInnerHTML` on the same JSX element."] NoDangerWithChildren,
    #[doc = "`<iframe>` element missing `sandbox` attribute."] IframeMissingSandbox, #[doc = "`javascript:` URL in JSX attribute."] JsxNoScriptUrl, #[doc = "`target=\"_blank\"` link without `rel=\"noreferrer\"` or `rel=\"noopener\"`."] JsxNoTargetBlank,
    #[doc = "`window.open` call without `'noopener'` in features."] WindowOpenWithoutNoopener, #[doc = "Hardcoded secret or client-exposed secret variable in browser code."] NoSecretsInClientCode, #[doc = "Persisting an authentication token in `localStorage` or `sessionStorage`."] AuthTokenInWebStorage,
    #[doc = "Dynamic code execution via `eval()`, `new Function()`, or string `setTimeout`/`setInterval`."] NoEval, #[doc = "Path containment check using `.startsWith(root)` without a trailing path separator."] NoPathPrefixContainment, #[doc = "`<ReactMarkdown>` with `rehype-raw` and no `rehype-sanitize` or sanitizer on dynamic content."] ReactMarkdownUnsanitizedRawHtml,
    #[doc = "Mismatched CSP `nonce` between `<ServerRouter>` and React server stream options."] ReactRouterCspNonceConsistency, #[doc = "Executable SVG asset or `dangerouslyAllowSVG: true` exposure."] ActiveStaticAsset, #[doc = "Agent tool definition exposing shell, filesystem, network, or code-execution primitives."] AgentToolCapabilityRisk,
    #[doc = "Browser artifact shipping Firebase/Supabase config together with sensitive collection/authz fields."] ArtifactBaasAuthoritySurface, #[doc = "Server secret environment variable names or full env dump leaked into a browser artifact."] ArtifactEnvLeak, #[doc = "Secret credential value shipped inside a browser artifact."] ArtifactSecretLeak,
    #[doc = "CI/build pipeline running lifecycle scripts without `--ignore-scripts` near secrets."] BuildPipelineSecretBoundary, #[doc = "Unvalidated redirect target or permissive framing (`frame-ancestors *` / `X-Frame-Options: ALLOW`)."] ClickjackingRedirectRisk, #[doc = "Shell or process command execution interpolated with caller-controlled request input."] CommandExecutionInputRisk,
    #[doc = "Credentialed CORS with wildcard/docs origin or broad parent-domain auth cookie."] CorsCookieTrustRisk, #[doc = "Dynamic HTML sink (`dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`) with unsanitized input."] DangerousHtmlSink, #[doc = "Client Firebase/Firestore write setting an ownership, tenant, or role authorization field."] FirebaseClientOwnedAuthzField,
    #[doc = "Permissive Firebase security rule (`allow read, write: if true` or `request.auth != null`)."] FirebasePermissiveRules, #[doc = "Firestore `.where(...)` client filter relied on as an authorization boundary."] FirebaseQueryFilterAsAuth, #[doc = "GitHub/GitLab/Bitbucket API URL built with unencoded caller-controlled interpolation."] GitProviderUrlInjectionRisk,
    #[doc = "Imported metadata, EXIF, manifest, or archive input reaching code/command execution."] ImportMetadataExecutionRisk, #[doc = "Weak cryptographic hash/cipher (`md5`, `sha1`, `DES`, `RC4`), `Math.random()` for secrets, or timing-unsafe signature comparison."] InsecureCryptoRisk, #[doc = "Auth/session cookie set without `HttpOnly` (`httpOnly: false` or `document.cookie`)."] InsecureSessionCookie,
    #[doc = "JWT verification configured with the `'none'` algorithm."] JwtInsecureVerification, #[doc = "Private key PEM block or long-lived signing/deploy key material committed in repository."] KeyLifecycleRisk, #[doc = "Localhost RPC or WebSocket native bridge exposing update/install/exec capabilities without strict origin checks."] LocalRpcNativeBridgeRisk,
    #[doc = "MCP server tool handler exposing raw shell, filesystem, network, or code-execution capability."] McpToolCapabilityRisk, #[doc = "Server-side MDX compilation (`compileMDX`, `MDXRemote`, `evaluateMdx`) over untrusted content or with `rehypeRaw`."] MdxSsrExecutionRisk, #[doc = "NoSQL query accepting `$where`, `$regex`, or unvalidated `JSON.parse(req.*)` operator input."] NosqlInjectionRisk,
    #[doc = "`package.json` metadata containing secret values, JWTs, or suspicious public env secret names."] PackageMetadataSecret, #[doc = "Filesystem read/write or `path.join`/`path.resolve` using unvalidated request/query/params input."] PathTraversalRisk, #[doc = "Remote script execution (`curl ... | sh`) or unsigned updater/plugin archive download without checksum verification."] PluginUpdateTrustRisk,
    #[doc = "`window.addEventListener('message', ...)` or `window.onmessage` reading `event.data` without checking `event.origin`."] PostmessageOriginRisk, #[doc = "Browser-reachable debug log, env dump, sql dump, or sourceless trace artifact under `public/`."] PublicDebugArtifact, #[doc = "Public client env variable (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`) named like a secret or private key."] PublicEnvSecretName,
    #[doc = "Raw SQL query built via string concatenation/interpolation or unsafe raw query helper (`$queryRawUnsafe`)."] RawSqlInjectionRisk, #[doc = "Committed `.env`, service-account JSON, `.npmrc`, or credential file containing live secrets."] RepositorySecretFile, #[doc = "Spreading or `Object.assign`/`_.merge`-ing raw `req.body`/`req.query` without a field allowlist."] RequestBodyMassAssignment,
    #[doc = "Secret environment variable read with a hardcoded string literal fallback (`process.env.SECRET ?? \"fallback\"`)."] SecretInFallback, #[doc = "Client Supabase `.insert`/`.update`/`.upsert` writing owner, tenant, or role authorization columns."] SupabaseClientOwnedAuthzField, #[doc = "Supabase SQL migration disabling RLS, granting `using (true)` write policies, or checking `auth.role() = 'service_role'`."] SupabaseRlsPolicyRisk,
    #[doc = "Supabase `create table` in `public` schema without `alter table ... enable row level security`."] SupabaseTableMissingRls, #[doc = "`<iframe>` rendered through an SVG/CSS `filter: url(#...)` clickjacking primitive."] SvgFilterClickjackingRisk, #[doc = "TanStack Start `createServerFn({ method: 'GET' })` performing a state mutation."] TanstackStartGetMutation,
    #[doc = "TanStack Start route `loader` accessing server-only secrets outside `createServerFn`."] TanstackStartNoSecretsInLoader, #[doc = "Server route composing tenant/subdomain/workspace input directly into a static/CDN/S3 asset fetch path."] TenantStaticProxyRisk, #[doc = "Unescaped `JSON.stringify(...)` injected into `dangerouslySetInnerHTML` or inline `<script>` markup."] UnsafeJsonInHtml,
    #[doc = "Server-side `fetch`/`axios`/`got` to a caller-controlled URL without `redirect: \"manual\"`."] UntrustedRedirectFollowing, #[doc = "Client code reading privileged action parameters (`role`, `admin`, `invite`, `redirect_uri`, `callbackUrl`) directly from URL searchParams."] UrlPrefilledPrivilegedAction, #[doc = "Webhook POST handler reading request payload without verifying the provider's cryptographic signature."] WebhookSignatureRisk,
    #[doc = "Blocking `console.*` or analytics/telemetry call in a Server Action or Route Handler not deferred with `after()`."] ServerAfterNonblocking, #[doc = "Calling a `React.cache(fn)` function with a fresh inline object or array literal argument."] ServerCacheWithObjectLiteral, #[doc = "Passing both a source array and a derived array (`.filter`, `.map`, `.slice`, `.toSorted`) as props from a Server Component."] ServerDedupProps,
    #[doc = "`fetch(url)` in a Next.js App Router server file without `cache` or `next: { revalidate }` / `next: { tags }`."] ServerFetchWithoutRevalidate, #[doc = "Static `fs.readFile*` or `fetch(new URL(..., import.meta.url))` inside a route handler instead of hoisted to module scope."] ServerHoistStaticIo, #[doc = "Mutable module-scope `let`/`var` or mutated `const` collection in a `\"use server\"` module shared across requests."] ServerNoMutableModuleState,
    #[doc = "Sequential `await` declarations of independent async operations that do not share cached work."] ServerSequentialIndependentAwait, #[doc = "`async` component function declared in a `\"use client\"` module."] NextjsAsyncClientComponent, #[doc = "Synchronous property access, destructuring, spread, or iteration on Next.js 15+ async `cookies()`, `headers()`, `draftMode()`, `params`, or `searchParams`."] NextjsAsyncDynamicApiNotAwaited,
    #[doc = "Next.js App Router `error.tsx` or `global-error.tsx` missing the `'use client'` directive."] NextjsErrorBoundaryMissingUseClient, #[doc = "Next.js App Router `global-error.tsx` missing root `<html>` and `<body>` elements."] NextjsGlobalErrorMissingHtmlBody, #[doc = "`<Image fill />` from `next/image` without a `sizes` attribute."] NextjsImageMissingSizes,
    #[doc = "Inline `<Script>` from `next/script` without an `id` attribute."] NextjsInlineScriptMissingId, #[doc = "Disagreement between `alternates.canonical` and `openGraph.url` in exported Next.js `metadata`."] NextjsMetadataUrlConsistency, #[doc = "Public Next.js App Router `page.tsx` without `metadata` or `generateMetadata` export and no ancestor layout metadata."] NextjsMissingMetadata,
    #[doc = "Plain `<a href=\"/...\">` for internal navigation in Next.js instead of `<Link>` from `next/link`."] NextjsNoAElement, #[doc = "`useEffect` + `fetch()` inside a `\"use client\"` Next.js page or layout instead of fetching in a Server Component."] NextjsNoClientFetchForServerData, #[doc = "Client-side redirect (`router.push` / `router.replace` / `window.location`) inside `useEffect` on mount."] NextjsNoClientSideRedirect,
    #[doc = "`<link rel=\"stylesheet\">` for local stylesheets bypassing Next.js CSS bundling."] NextjsNoCssLink, #[doc = "`export default` in a Next.js App Router `route.ts` file without named HTTP method exports."] NextjsNoDefaultExportInRouteHandler, #[doc = "`export const runtime = 'edge'` inside an `opengraph-image` or `twitter-image` route."] NextjsNoEdgeOgRuntime,
    #[doc = "Loading Google Fonts via `<link href=\"https://fonts.googleapis.com/...\">` instead of `next/font/google`."] NextjsNoFontLink, #[doc = "Manual Google Analytics `<script>` / `<Script>` tag instead of `@next/third-parties/google`."] NextjsNoGoogleAnalyticsScript, #[doc = "Importing `next/head` inside the Next.js App Router (`app/` directory)."] NextjsNoHeadImport,
    #[doc = "Native `<script src=\"...\">` tag in Next.js instead of `<Script>` from `next/script`."] NextjsNoNativeScript, #[doc = "Loading redundant polyfill CDN scripts (`polyfill.io`) already bundled by Next.js."] NextjsNoPolyfillScript, #[doc = "Calling `redirect()`, `permanentRedirect()`, `notFound()`, `forbidden()`, or `unauthorized()` inside a `try` block without `unstable_rethrow`."] NextjsNoRedirectInTryCatch,
    #[doc = "Rendering `next/script` `<Script>` inside `next/head` `<Head>`."] NextjsNoScriptInHead, #[doc = "Performing state mutations, cookie writes, or mutating fetches inside a Next.js `GET` route handler."] NextjsNoSideEffectInGetHandler, #[doc = "Calling `useSearchParams()` in a Next.js page/layout without an enclosing `<Suspense>` boundary."] NextjsNoUseSearchParamsWithoutSuspense,
    #[doc = "Importing `@vercel/og` directly instead of `next/og`."] NextjsNoVercelOgImport, #[doc = "Missing or weakened pnpm supply-chain hardening settings (`minimumReleaseAge`, `blockExoticSubdeps`, `trustPolicy`) in `pnpm-workspace.yaml`."] RequirePnpmHardening, #[doc = "Installed `react-server-dom-*` or `next` version affected by React Server Components RCE (CVE-2025-55182) or DoS (CVE-2026-23870) advisories."] NoVulnerableReactServerComponents,
    #[doc = "Direct dependency scoring below the minimum threshold on Socket.dev's supply-chain or vulnerability security axes."] LowSupplyChainScore, #[doc = "Spreading a whole TanStack Query result subscribes to every field."] QueryDestructureResult, #[doc = "Unhandled floating `mutateAsync()` promise from TanStack `useMutation`."] QueryFloatingMutateAsync,
    #[doc = "TanStack `useMutation` missing cache invalidation or update in lifecycle callbacks."] QueryMutationMissingInvalidation, #[doc = "Invoking a read-style TanStack `useMutation` inside `useEffect` instead of `useQuery`."] QueryNoMutationInEffectAsRead, #[doc = "Calling TanStack Query `refetch()` unconditionally inside `useEffect`."] QueryNoQueryInEffect,
    #[doc = "Rest-destructuring a TanStack Query result (`const { data, ...rest } = useQuery(...)`)."] QueryNoRestDestructuring, #[doc = "Using TanStack `useQuery` for an HTTP mutation (`POST`/`PUT`/`PATCH`/`DELETE`)."] QueryNoUseQueryForMutation, #[doc = "Constructing `new QueryClient()` inside a component render body."] QueryStableQueryClient,
    #[doc = "Independent sequential `await` expressions inside a TanStack Start route `loader`."] TanstackStartLoaderParallelFetch, #[doc = "Root route `<head>` missing `<HeadContent />` in TanStack Start."] TanstackStartMissingHeadContent, #[doc = "Root route `<body>` missing `<Scripts />` in TanStack Start."] TanstackStartMissingScripts,
    #[doc = "Plain `<a href=\"/...\">` internal link in TanStack Start routes instead of `<Link>`."] TanstackStartNoAnchorElement, #[doc = "Retired rule: direct `fetch` inside a TanStack Start route loader."] TanstackStartNoDirectFetchInLoader, #[doc = "Dynamic `import(\"*.functions\")` of a TanStack Start server functions module."] TanstackStartNoDynamicServerFnImport,
    #[doc = "Calling `navigate()` synchronously during render in TanStack Start."] TanstackStartNoNavigateInRender, #[doc = "Calling `fetch()` inside `useEffect` in a TanStack Start route instead of `loader`."] TanstackStartNoUseEffectFetch, #[doc = "Redundant `\"use server\"` directive inside a TanStack Start `createServerFn` `.handler(...)`."] TanstackStartNoUseServerInHandler,
    #[doc = "`throw redirect()` or `throw notFound()` caught by an enclosing `try`/`catch` without re-throwing."] TanstackStartRedirectInTryCatch, #[doc = "Out-of-order route options properties in `createFileRoute` / `createRoute` breaking type inference."] TanstackStartRoutePropertyOrder, #[doc = "Out-of-order `createServerFn` chained methods breaking type inference."] TanstackStartServerFnMethodOrder,
    #[doc = "Retired rule: animating layout properties in React Native."] RnAnimateLayoutProperty, #[doc = "Using `useAnimatedReaction` solely to copy one shared value into another instead of `useDerivedValue`."] RnAnimationReactionAsDerived, #[doc = "Passing ignored scroll props (`scrollEventThrottle`, `decelerationRate`, `onScrollBeginDrag`) to `BottomSheetScrollView`."] RnBottomSheetNoIgnoredScrollProp,
    #[doc = "Updating React state inside `@gorhom/bottom-sheet` `onAnimate`."] RnBottomSheetNoStateInOnAnimate, #[doc = "Importing a JS-driven bottom sheet library instead of native `formSheet` modal presentation."] RnBottomSheetPreferNative, #[doc = "Nesting React Native scrollables inside `@gorhom/bottom-sheet` instead of integrated `BottomSheet*` scrollables."] RnBottomSheetUseIntegratedScrollable,
    #[doc = "Un-awaited Detox element action, `waitFor`, or `expect` call in E2E tests."] RnDetoxMissingAwait, #[doc = "Creating an inline press handler closure per row inside list `renderItem`."] RnListCallbackPerRow, #[doc = "Passing a freshly allocated `.map()` / `.filter()` / `[...]` array to list `data`."] RnListDataMapped,
    #[doc = "`FlashList` or `LegendList` missing `estimatedItemSize`."] RnListMissingEstimatedItemSize, #[doc = "Heterogeneous root item shapes in `FlashList` / `LegendList` `renderItem` without `getItemType`."] RnListRecyclableWithoutTypes, #[doc = "Deep subpath import from `react-native/Libraries/*` for a root-exported symbol or `NewAppScreen`."] RnNoDeepImports,
    #[doc = "Importing removed core modules (`AsyncStorage`, `WebView`, `NetInfo`, `Clipboard`, etc.) from `react-native`."] RnNoDeprecatedModules, #[doc = "Calling `Dimensions.get(...)` inside a component or hook instead of `useWindowDimensions()`."] RnNoDimensionsGet, #[doc = "Numeric or string falsy `&&` short-circuit (`{count && <View />}`) that crashes when rendering `0` or `\"\"` on React Native."] RnNoFalsyAndRender,
    #[doc = "Passing children to React Native `<Image>` instead of `<ImageBackground>`."] RnNoImageChildren, #[doc = "Passing an inline function to `renderItem` on a React Native virtualized list."] RnNoInlineFlatlistRenderitem, #[doc = "Passing an inline object literal prop to a component inside list `renderItem`."] RnNoInlineObjectInListItem,
    #[doc = "Importing unmaintained legacy Expo packages (`expo-av`, `expo-permissions`, `expo-app-loading`, `react-native-fast-image`)."] RnNoLegacyExpoPackages, #[doc = "Using platform-specific legacy shadow style properties (`shadowColor`, `elevation`, etc.)."] RnNoLegacyShadowStyles, #[doc = "Importing JS-driven `@react-navigation/stack` or `@react-navigation/drawer` instead of `@react-navigation/native-stack`."] RnNoNonNativeNavigator,
    #[doc = "Importing `PanResponder` from `react-native` instead of `react-native-gesture-handler`."] RnNoPanresponder, #[doc = "Redundant `key` prop on the root JSX element returned from list `renderItem`."] RnNoRenderitemKey, #[doc = "Updating React state inside an `onScroll` handler on React Native."] RnNoScrollState,
    #[doc = "Rendering an unbounded `.map()` list inside `<ScrollView>` instead of `FlatList` / `FlashList`."] RnNoScrollviewMappedList, #[doc = "Retired rule: imperative `setNativeProps` calls in React Native."] RnNoSetNativeProps, #[doc = "Retired rule: single-element style array in React Native."] RnNoSingleElementStyleArray,
    #[doc = "Accessing `RN.Platform` via a `react-native` namespace import in Expo SDK 54+."] RnPlatformShakingUseDirectImport, #[doc = "Retired rule: manual safe-area inset padding vs. `contentInsetAdjustmentBehavior`."] RnPreferContentInsetAdjustment, #[doc = "Importing `Image` from `react-native` instead of `expo-image` in an Expo project."] RnPreferExpoImage,
    #[doc = "Wrapping a simple single-tap `Gesture.Tap()` in `<GestureDetector>` instead of `<Pressable>`."] RnPreferPressableOverGestureDetector, #[doc = "Importing legacy `Touchable*` components instead of `Pressable`."] RnPreferPressable, #[doc = "Retired rule: importing `Animated` from `react-native` instead of `react-native-reanimated`."] RnPreferReanimated,
    #[doc = "Mutating a Reanimated shared value inside `<Pressable>` JS press handlers instead of UI-thread `Gesture.Tap()`."] RnPressableSharedValueMutation, #[doc = "Passing removed Reanimated 3 spring rest thresholds (`restDisplacementThreshold`, `restSpeedThreshold`) in Reanimated 4."] RnReanimated4NoLegacySpringThresholds, #[doc = "Calling removed Reanimated 3 APIs (`useAnimatedGestureHandler`, `useWorkletCallback`, `combineTransition`, `addWhitelisted*Props`) in Reanimated 4."] RnReanimated4NoRemovedApi,
    #[doc = "Calling worklet schedulers (`runOnUI`, `runOnJS`, `executeOnUIRuntimeSync`, `runOnRuntime`) from `react-native-reanimated` in Reanimated 4."] RnReanimated4UseWorkletsScheduler, #[doc = "Dynamic `paddingTop` or `paddingBottom` on `ScrollView` `contentContainerStyle`."] RnScrollviewDynamicPadding, #[doc = "Using `flex: 1` shorthand on `ScrollView` `contentContainerStyle` instead of `flexGrow: 1`."] RnScrollviewFlexInContentContainer,
    #[doc = "Using legacy iOS/Android shadow style properties instead of unified CSS `boxShadow`."] RnStylePreferBoxShadow, #[doc = "Referencing removed `module:metro-react-native-babel-preset` on React Native 0.73+."] RnNoMetroBabelPreset, #[doc = "Using `module:@react-native/babel-preset` without an `enableBabelRuntime` version string."] RnNoMetroBabelRuntimeVersion,
    #[doc = "Listing `react` or `react-native` in `dependencies` of a `react-native-builder-bob` library."] RnLibraryReactInDependencies, #[doc = "Placing `babel-plugin-react-compiler` after other plugins in Babel `plugins`."] RnReactCompilerPluginFirst, #[doc = "Using legacy `react-native-reanimated/plugin` or placing `react-native-worklets/plugin` non-last in Reanimated 4."] RnReanimatedWorkletsPluginLast,
    #[doc = "Disabling `minifyEnabled` or `shrinkResources` in Android `buildTypes.release`."] RnAndroidReleaseShrinkingDisabled, #[doc = "Declaring legacy `@unimodules/*` or `react-native-unimodules` dependencies in Expo."] ExpoNoUnimodulesPackages, #[doc = "Declaring global CLIs (`expo-cli`, `eas-cli`) in project dependencies."] ExpoNoCliDependencies,
    #[doc = "Declaring redundant or removed transitive Expo SDK packages directly in `package.json`."] ExpoNoRedundantDependency, #[doc = "Overriding Expo SDK-critical packages (`metro`, `@expo/cli`, `@expo/metro-config`, etc.) via `overrides`/`resolutions`."] ExpoNoConflictingDependencyOverride, #[doc = "Installing `@react-navigation/*` directly alongside `expo-router` on Expo SDK 56."] ExpoRouterNoReactNavigation,
    #[doc = "Mixing scoped `@react-native-vector-icons/*` with `@expo/vector-icons` or `react-native-vector-icons` on Expo SDK 56+."] ExpoVectorIconsConflict, #[doc = "Defining `expo`/`react-native` scripts or a package `name` that collides with a dependency in `package.json`."] ExpoPackageJsonConflict, #[doc = "Missing or multiple package manager lockfiles at the Expo workspace root."] ExpoLockfile,
    #[doc = "Custom `metro.config.*` in an Expo project that does not extend `expo/metro-config`."] ExpoMetroConfig, #[doc = "Un-gitignored `.env*.local` files in an Expo repository."] ExpoEnvLocalNotGitignored, #[doc = "Un-gitignored `.expo/` state directory or gitignored local module `modules/*/ios|android` native directories."] ExpoGitignore,
    #[doc = "`newArchEnabled: false` in `app.json` while using Reanimated 4 or `react-native-worklets`."] ExpoReanimatedV4RequiresNewArch, #[doc = "`updates.disableAntiBrickingMeasures: true` in `app.json`."] ExpoUpdatesNoUnsafeProductionConfig, #[doc = "Mutating Zustand state in place and reusing the same reference in `set(...)` or `setState(...)`."] ZustandNoMutatingState,
    #[doc = "Returning a fresh object or array from a Zustand store selector without `useShallow`."] ZustandNoFreshSelectorResult, #[doc = "Calling Zustand `get()` synchronously during store initialization."] ZustandNoGetDuringInitialization, #[doc = "Returning a fresh object or array from a Jotai derived `atom((get) => ...)`."] JotaiDerivedAtomReturnsFreshObject,
    #[doc = "Subscribing directly to a `jotai-tanstack-query` `atomWithQuery` envelope atom in render."] JotaiTqUseRawQueryAtom, #[doc = "Wrapping an already `memo`-ized or `observer`-wrapped component in MobX `observer(...)`."] MobxNoObserverWrappedMemo, #[doc = "Calling `makeAutoObservable(this)` in a class that uses inheritance (`extends` or subclassed)."] MobxNoMakeAutoObservableInInheritance,
    #[doc = "Reading a Valtio proxy directly during render when `useSnapshot(proxy)` is active."] ValtioNoProxyReadInRender, #[doc = "Using `onChange` instead of `onInput` on text-like `<input>` / `<textarea>` in pure Preact."] PreactPreferOninput, #[doc = "Using `onDoubleClick` instead of `onDblClick` on host elements in pure Preact."] PreactPreferOndblclick,
    #[doc = "Reading `render(props, state)` parameters in a Preact class component instead of `this.props` / `this.state`."] PreactNoRenderArguments, #[doc = "Importing hooks from `'react'` instead of `'preact/hooks'` in pure Preact."] PreactNoReactHooksImport, #[doc = "Accessing `.length` or array methods directly on `children` / `props.children` in Preact without `toChildArray`."] PreactNoChildrenLength,
    #[doc = "Handling Ctrl-C in Ink `useInput` without passing `{ exitOnCtrlC: false }` to `render()`."] InkCtrlCHandlerRequiresExitOption, #[doc = "Retired rule: `<Newline>` placement inside Ink `<Text>`."] InkNewlineInsideText, #[doc = "Calling `process.exit()` directly inside an Ink `useInput` handler instead of `useApp().exit()`."] InkNoBareProcessExit,
    #[doc = "Calling `useStdin().setRawMode()` synchronously during render in Ink."] InkNoDirectRawMode, #[doc = "Rendering DOM host elements (`<div>`, `<span>`, etc.) inside an Ink terminal tree."] InkNoDomHostElements, #[doc = "Using DOM-dependent router components (`BrowserRouter`, `HashRouter`, `Link` from `react-router-dom`) in Ink."] InkNoDomRouter,
    #[doc = "Calling `useFocusManager().focus*()` synchronously during render in Ink."] InkNoFocusInRender, #[doc = "Nesting Ink layout components (`<Box>`, `<Spacer>`, `<Static>`) inside `<Text>` or `<Transform>`."] InkNoLayoutInsideText, #[doc = "Using live input hooks (`useInput`, `usePaste`) in a component rendered only via `renderToString()`."] InkNoLiveHooksInRenderToString,
    #[doc = "Calling Ink `measureElement()` synchronously during render."] InkNoMeasureElementInRender, #[doc = "Rendering multiple unconditional `<Static>` regions in a single Ink component root."] InkNoMultipleStatic, #[doc = "Calling Ink `render()` repeatedly on the same output stream without unmounting or calling `rerender()`."] InkNoRepeatedRender,
    #[doc = "Driving a manual `setInterval` frame counter in `useEffect` instead of Ink `useAnimation()`."] InkPreferUseAnimation, #[doc = "Inferring paste events from `useInput` newline/length checks instead of Ink `usePaste()`."] InkPreferUsePaste, #[doc = "Passing a reordered/mutated collection (`.sort()`, `.reverse()`, `.toSorted()`, `.toReversed()`) to Ink `<Static items={...}>`."] InkStaticIsAppendOnly,
    #[doc = "Missing `key` prop on the root JSX element returned by an Ink `<Static>` render function."] InkStaticRequiresKey, #[doc = "Retired rule: Ink `<Suspense>` concurrent rendering mode."] InkSuspenseRequiresConcurrent, #[doc = "Reading `process.stdout.columns` or `process.stdout.rows` in Ink render without a resize listener or `useWindowSize()`."] InkUseReactiveWindowSize,
    #[doc = "Using `.length` instead of `string-width` for horizontal cursor column offset in `useCursor().setCursorPosition()`."] InkUseStringWidthForCursor, #[doc = "Spawning an interactive child process (`stdio: \"inherit\"`) inside Ink `useInput` without `useApp().suspendTerminal()`."] InkUseSuspendTerminal, #[doc = "Using deprecated `z.string().email()` / `.uuid()` / `.url()` method chains instead of top-level Zod 4 format functions."] ZodV4PreferTopLevelStringFormats,
    #[doc = "Using deprecated Zod 3 schema APIs (`z.nativeEnum`, `z.object().strict()`, `z.record(valueSchema)`, `z.function().args()`, etc.) in Zod 4."] ZodV4NoDeprecatedSchemaApis, #[doc = "Using deprecated Zod 3 error customization (`invalid_type_error`, `required_error`, `errorMap`) in Zod 4."] ZodV4NoDeprecatedErrorCustomization, #[doc = "Using removed `ZodError` APIs (`.flatten()`, `.format()`, `.formErrors`, `.errors`, `.addIssue()`, `ZodError.create()`) in Zod 4."] ZodV4NoDeprecatedErrorApis,
    #[doc = "Updating a State Slot inside an Effect Node that tracks that same State Slot without converging."] NoSelfUpdatingEffect, #[doc = "Calling a state setter unconditionally at the top level of a component render body."] NoSetStateInRender, #[doc = "Calling a state setter after an `await` inside `useEffect` without a cancellation guard."] NoSetStateAfterAwaitInEffect,
    #[doc = "Reading or writing `ref.current` during component render."] NoRefCurrentInRender, #[doc = "Invoking a prop callback directly during component render."] NoPropCallbackInRender, #[doc = "Synchronously invoking a prop callback inside `useEffect`."] NoPropCallbackInEffect,
    #[doc = "Performing side effects inside a `setState(prev => ...)` updater callback."] NoSideEffectInStateUpdaterFunction, #[doc = "Reading a stale timer ref or failing to clear/store a timer ref properly."] NoStaleTimerRef, #[doc = "Clearing an async error state unconditionally before an unowned async operation."] NoUnownedAsyncErrorClear,
    #[doc = "Listing a whole object in hook dependencies when only specific properties are read."] NoWholeObjectDepWithMemberReads, #[doc = "Spreading props after default properties in an object literal (`{ a: 1, ...props }`)."] NoSpreadPropsOverDefaultsClobbersWithUndefined, #[doc = "Component manages many coupled `useState` slots that should be consolidated into `useReducer`."] PreferUseReducer,
    #[doc = "Effect reads a reactive value only for logging/event notification and re-runs unnecessarily."] PreferUseEffectEvent, #[doc = "Calling `setState(state + 1)` with direct state read instead of functional updater `setState(s => s + 1)`."] RerenderFunctionalSetstate, #[doc = "Passing an expensive call expression directly to `useState(expensive())` instead of `useState(() => expensive())`."] RerenderLazyStateInit,
    #[doc = "Passing an expensive construction directly to `useRef(new Expensive())` on every render."] RerenderLazyRefInit, #[doc = "State Slot is only read inside event handlers and never affects rendered output."] RerenderStateOnlyInHandlers, #[doc = "Calling a hook whose return value is only used after an early return or inside callbacks."] RerenderDeferReadsHook,
    #[doc = "Passing unstable or overly broad dependencies to an effect or memo hook."] RerenderDependencies, #[doc = "Registering an event listener, timer, or subscription in `useEffect` without a cleanup return."] EffectNeedsCleanup, #[doc = "Calling a React Hook conditionally, in a loop, or outside a component/custom hook."] RulesOfHooks,
    #[doc = "`<input checked>` without `onChange` or `readOnly`, or mixing `checked` with `defaultChecked`."] CheckedRequiresOnchangeOrReadonly, #[doc = "`<button>` inside a form or with invalid/missing explicit `type` attribute."] ButtonHasType, #[doc = "Redundant `<></>` or `<Fragment>` wrapping a single child or empty content."] JsxNoUselessFragment,
    #[doc = "Explicit `={true}` on a boolean JSX attribute (`<Comp disabled={true} />`)."] JsxBooleanValue, #[doc = "Unnecessary curly braces around a string literal in JSX (`<Comp title={\"hello\"} />`)."] JsxCurlyBracePresence, #[doc = "Using `<React.Fragment>` instead of shorthand `<>...</>` when no `key` is present."] JsxFragments,
    #[doc = "User-defined JSX component name not using PascalCase (`<my_component />`)."] JsxPascalCase, #[doc = "Spreading arbitrary props onto a JSX element (`<Comp {...props} />`)."] JsxPropsNoSpreading, #[doc = "JSX nesting depth exceeds configured maximum depth."] JsxMaxDepth,
    #[doc = "Non-void JSX element with no children written with a closing tag (`<Comp></Comp>`)."] SelfClosingComp, #[doc = "`style` attribute on JSX element is not an object expression (`style=\"color: red\"`)."] StylePropObject, #[doc = "Unknown or non-standard DOM property on an intrinsic JSX element (`<div class=\"foo\" />`)."] NoUnknownProperty,
    #[doc = "Defining a nested component inside another component (`no-unstable-nested-components`)."] NoUnstableNestedComponents, #[doc = "Non-standard or asymmetric `[val, setVal] = useState()` naming."] HookUseState, #[doc = "Component wrapped in `memo` or `forwardRef` missing a `displayName` or named function."] DisplayName,
    #[doc = "Legacy string `ref=\"myRef\"` on a JSX element."] NoStringRefs, #[doc = "Usage of `UNSAFE_componentWillMount`, `UNSAFE_componentWillReceiveProps`, or `UNSAFE_componentWillUpdate`."] NoUnsafe, #[doc = "Calling `this.setState` inside `componentDidMount`."] NoDidMountSetState,
    #[doc = "Calling `this.setState` inside `componentDidUpdate`."] NoDidUpdateSetState, #[doc = "Calling `this.setState` inside `componentWillUpdate`."] NoWillUpdateSetState, #[doc = "Initializing state outside constructor or both in constructor and class property."] StateInConstructor,
    #[doc = "Using `createReactClass` instead of ES6 `class extends React.Component`."] PreferEs6Class, #[doc = "Stateless class component that can be written as a function component."] PreferFunctionComponent, #[doc = "Passing a freshly allocated array or `.filter()`/`.map()`/`.concat()` result as a JSX prop."] JsxNoNewArrayAsProp,
    #[doc = "Passing an inline arrow/function expression or `.bind()` as a JSX prop."] JsxNoNewFunctionAsProp, #[doc = "Using `Math.random()`, `Date.now()`, `crypto.randomUUID()`, or `nanoid()` in a JSX `key`."] NoRandomKey, #[doc = "Numeric expression before `&&` in JSX (`{items.length && <List />}`) rendering a stray `0`."] RenderingConditionalRender,
    #[doc = "Calling `event.preventDefault()` in an invalid or passive handler context."] NoPreventDefault, #[doc = "Invalid `offset` values in Web Animations API `element.animate(keyframes)`."] WebAnimationOffsetsValid, #[doc = "Mixing controlled `value` and uncontrolled `defaultValue` or passing `value={undefined}`."] NoUncontrolledInput,
    #[doc = "Constant literal in logical `||` / `&&` comparison chain (`x === 'a' || 'b'`)."] NoCollapsedLiteralOrChainAsValue, #[doc = "Consuming `await response.json()` without checking `response.ok` or `response.status`."] NoFetchResponseUsedWithoutStatusCheck, #[doc = "Calling `.sort()`, `.reverse()`, or `.splice()` directly on a prop or hook result array."] NoMutatingArrayMethodOnPropOrHookResult,
    #[doc = "Nesting `<form>` inside another `<form>`."] HtmlNoNestedForm, #[doc = "Placing `<tr>` directly inside `<table>` without `<thead>`, `<tbody>`, or `<tfoot>`."] HtmlNoInvalidTableNesting, #[doc = "Defining a React component inside another component's body."] NoNestedComponentDefinition,
    #[doc = "Static array or object literal declared inside a component body instead of module scope."] PreferModuleScopeStaticValue, #[doc = "Pure helper function with no component-local captures declared inside a component body."] PreferModuleScopePureFunction, #[doc = "Manual `useMemo`/`useCallback`/`memo` when React Compiler is active."] ReactCompilerNoManualMemoization,
    #[doc = "Assigning `.defaultProps` on a function component instead of using default parameters."] NoDefaultProps, #[doc = "Assigning `.propTypes` instead of TypeScript prop types."] NoPropTypes, #[doc = "Using legacy React `contextTypes`, `childContextTypes`, or `getChildContext`."] NoLegacyContextApi,
    #[doc = "Using legacy `componentWillMount`, `componentWillReceiveProps`, or `componentWillUpdate`."] NoLegacyClassLifecycles, #[doc = "Invoking a higher-order component factory inside a render body."] NoInlineHocOnComponent, #[doc = "Component exceeds maintainable line/statement complexity size."] NoGiantComponent,
    #[doc = "React component or hook exceeds cyclomatic/branching complexity threshold."] NoHighComplexityReactFunction, #[doc = "Component accepts too many boolean flag props instead of explicit variants."] NoManyBooleanProps, #[doc = "Generic handler name (`handleClick`, `onChange`) that obscures domain intent."] NoGenericHandlerNames,
    #[doc = "Calling a `renderFoo()` helper function inside JSX instead of extracting a child component."] NoRenderInRender, #[doc = "Using APIs deprecated in React 19 (`forwardRef`, `React.createFactory`, `defaultProps`)."] NoReact19DeprecatedApis, #[doc = "Using deprecated `react-dom` APIs (`ReactDOM.render`, `ReactDOM.hydrate`, `findDOMNode`)."] NoReactDomDeprecatedApis,
    #[doc = "`Context.Provider` bundles frequently mutated State Slots with static fields read by static-only consumers."] OverloadedContextProvider, #[doc = "Subject invoking suspending hooks/APIs or throwing boundaries lacks an ancestral `<Suspense>` or `<ErrorBoundary>` across Caller Sites."] MissingSuspenseOrErrorBoundary, #[doc = "Activity wraps an effect-heavy subtree."] ActivityWrapsEffectHeavySubtree,
    #[doc = "Listener re-subscribes on every handler change."] AdvancedEventHandlerRefs, #[doc = "Base UI tab is outside Tabs.List."] BaseUiTabsTabRequiresList, #[doc = "Class component acquires a resource with no teardown."] ClassComponentMissingComponentWillUnmountTeardown,
    #[doc = "Memoized debounce never cancelled on unmount."] DebounceNoCleanup, #[doc = "Effect cleanup does not match its event listener."] EffectListenerCleanupMismatch, #[doc = "Effect cleanup removes the wrong listener reference."] EffectListenerCleanupReferenceMismatch,
    #[doc = "Observer created in an effect never disconnected."] EffectObserverNeedsDisconnect, #[doc = "requestAnimationFrame loop never cancelled."] EffectRafLoopNeedsCancel, #[doc = "removeEventListener called with a fresh inline handler."] EffectRemoveListenerInlineHandler,
    #[doc = "Blocked component prop bypasses API contract."] ForbidComponentProps, #[doc = "Blocked DOM prop bypasses project contract."] ForbidDomProps, #[doc = "Blocked element bypasses approved UI primitives."] ForbidElements,
    #[doc = "forwardRef without ref parameter."] ForwardRefUsesRef, #[doc = "Hook import alias disables hook lint checks."] HookImportRenameLosesUsePrefix, #[doc = "NaN in a hook dependency array."] HooksNoNanInDeps,
    #[doc = "Label wraps multiple native controls."] HtmlLabelHasSingleControl, #[doc = "Block element inside a paragraph."] HtmlNoInvalidParagraphChild, #[doc = "JSX in disallowed file extension."] JsxFilenameExtension,
    #[doc = "Comment rendered as JSX text."] JsxNoCommentTextnodes, #[doc = "Duplicate props on element."] JsxNoDuplicateProps, #[doc = "JSX element passed as a prop."] JsxNoJsxAsProp,
    #[doc = "Same prop spread multiple times."] JsxPropsNoSpreadMulti, #[doc = "AnimatePresence unmounts with its exiting child."] MotionAnimatePresenceMustOutliveChild, #[doc = "AnimatePresence child is missing a key."] MotionAnimatePresenceRequiresKey,
    #[doc = "AnimatePresence wait mode has multiple children."] MotionAnimatePresenceWaitSingleChild, #[doc = "Motion component is created during render."] MotionCreateInRender, #[doc = "Motion drag constraints do not match the drag axis."] MotionDragAxisConstraintMismatch,
    #[doc = "Imperative Motion animation runs during render."] MotionImperativeAnimationInRender, #[doc = "Motion keyframes and times have different lengths."] MotionKeyframeTimesMismatch, #[doc = "Motion layout animation targets an inline element."] MotionLayoutOnInlineElement,
    #[doc = "Motion layout ID is unstable in an iteration."] MotionUnstableLayoutIdInIteration, #[doc = "Motion transform ranges have different lengths."] MotionUseTransformRangeLength, #[doc = "Motion value subscription is created during render."] MotionValueSubscriptionInRender,
    #[doc = "Multiplicative math on optional-chained value can be NaN."] NoArithmeticOnOptionalChainedOperand, #[doc = "Unguarded member access on find() result."] NoArrayFindResultMemberAccessWithoutGuard, #[doc = "Array index result dereferenced without a guard."] NoArrayIndexDerefWithoutBoundsOrEmptyGuard,
    #[doc = "Async effect callback."] NoAsyncEffectCallback, #[doc = "Async mutating handler without re-entry guard."] NoAsyncEventHandlerWithoutReentryGuard, #[doc = "Boolean toggle reads a stale value."] NoBooleanToggleWithoutFunctionalUpdate,
    #[doc = "Component called as a function."] NoCallComponentAsFunction, #[doc = "Multiple setState calls in one effect."] NoCascadingSetState, #[doc = "Children passed as a prop."] NoChildrenProp,
    #[doc = "cloneElement makes child props fragile."] NoCloneElement, #[doc = "Request failure rendered as an empty result."] NoCollapseRequestErrorToEmptyState, #[doc = "createContext called during render."] NoCreateContextInRender,
    #[doc = "Object URL is created during render."] NoCreateObjectUrlInRender, #[doc = "createRef in function component."] NoCreateRefInFunctionComponent, #[doc = "Store created during render."] NoCreateStoreInRender,
    #[doc = "Deprecated KeyboardEvent keyCode or which."] NoDeprecatedKeyboardEventKeycodeWhich, #[doc = "Effect Event listed in effect deps."] NoEffectEventInDeps, #[doc = "Effect dependency recreated every render."] NoEffectWithFreshDeps,
    #[doc = "Effect wrapper discards forwarded cleanup return."] NoEffectWrapperDiscardsCallbackCleanupReturn, #[doc = "Enter submit without IME composition guard."] NoEnterSubmitWithoutImeCompositionGuard, #[doc = "fill().map() first param is the element, not the index."] NoFillMapElementAsKey,
    #[doc = "findDOMNode breaks component encapsulation."] NoFindDomNode, #[doc = "Floating .then in a JSX event handler."] NoFloatingThenInJsxHandler, #[doc = "Nondeterministic built-in at module scope."] NoImpureCallAtModuleScope,
    #[doc = "State updater has side effects."] NoImpureStateUpdater, #[doc = "Indeterminate checkbox state set as an attribute."] NoIndeterminateAttribute, #[doc = "isMounted lets async callbacks update after unmount."] NoIsMounted,
    #[doc = "No JSX.Element."] NoJsxElementType, #[doc = "Loading flag reset outside finally."] NoLoadingFlagResetOutsideFinally, #[doc = "srcSet mixes width and density descriptors."] NoMixedSrcsetDescriptors,
    #[doc = "Multiple components in one file."] NoMultiComp, #[doc = "Crowded component file."] NoMultiComponentFile, #[doc = "Mutable value in effect dependencies."] NoMutableInDeps,
    #[doc = "Mutating a queried DOM node this component renders."] NoMutateQueriedDomNodeInComponent, #[doc = "State mutated in place then set by same reference."] NoMutateThenSetOrReturnSameReference, #[doc = "Reducer mutates its state."] NoMutatingReducerState,
    #[doc = "Namespaced JSX element."] NoNamespace, #[doc = "Unguarded querySelector with href-derived selector."] NoNonLiteralSelectorQueryWithoutTryCatch, #[doc = "Non-null assertion on a maybe-undefined result."] NoNonNullAssertionOnMaybeUndefinedResult,
    #[doc = "Nondeterministic id generated in render body."] NoNondeterministicIdValueInRenderBody, #[doc = "Nullish coalescing swallowed by adjacent arithmetic."] NoNullishCoalescingArithmeticPrecedence, #[doc = "Object.keys/values/entries on maybe-undefined value."] NoObjectKeysValuesEntriesOnMaybeUndefined,
    #[doc = "Object or lossy array coerced in a template literal."] NoObjectOrArrayCoercedToStringInTemplateLiteral, #[doc = "Passive owner ref leaves a stale-request window."] NoPassiveRequestOwnerRef, #[doc = "Children type checked at runtime."] NoPolymorphicChildren,
    #[doc = "Predicate function used without calling it."] NoPredicateFunctionReferenceInBooleanPosition, #[doc = "Effect promise .then sets state with no catch."] NoPromiseThenSideEffectInEffectWithoutCatch, #[doc = "React.Children is fragile when child shape changes."] NoReactChildren,
    #[doc = "Redundant shouldComponentUpdate."] NoRedundantShouldComponentUpdate, #[doc = "Ref cleanup requires React 19."] #[serde(rename = "no-ref-callback-cleanup-before-react-19")] NoRefCallbackCleanupBeforeReact19, #[doc = "Using ReactDOM.render return value."] NoRenderReturnValue,
    #[doc = "Local class state forbidden."] NoSetState, #[doc = "String true/false on a boolean attribute."] NoStringFalseOnBooleanAttribute, #[doc = "this used in function component."] NoThisInSfc,
    #[doc = "Unescaped dynamic string in RegExp constructor."] NoUnescapedDynamicStringInRegexp, #[doc = "Unescaped entities in JSX."] NoUnescapedEntities, #[doc = "Browser global read at module scope."] NoUnguardedBrowserGlobalAtModuleScope,
    #[doc = "Unguarded numeric parse of an input value."] NoUnguardedNumericInputParse, #[doc = "Unguarded call to a throwing parse API."] NoUnguardedThrowingParseCall, #[doc = "Unsafe JSON.parse dereference."] NoUnsafeJsonParse,
    #[doc = "Whole-object param default loses per-key defaults."] NoWholeObjectDefaultLosingPerKeyDefaults, #[doc = "Captured pointer interaction has no cancellation path."] PointerCaptureNeedsCancelHandler, #[doc = "Radix tabs trigger is outside Tabs.List."] RadixTabsTriggerRequiresList,
    #[doc = "React not in scope for JSX."] ReactInJsxScope, #[doc = "Parent path cannot match descendant routes."] ReactRouterDescendantRoutesRequireSplat, #[doc = "Aborted requests are reported as errors."] ReactRouterGuardAbortedHandleError,
    #[doc = "Internal route uses a document navigation."] ReactRouterInternalRouteAnchor, #[doc = "Nested routes have no Outlet."] ReactRouterNestedRouteRequiresOutlet, #[doc = "Middleware catch cannot observe downstream errors."] ReactRouterNoCatchMiddlewareNext,
    #[doc = "Client-only module rendered on the server."] ReactRouterNoClientModuleInServerRender, #[doc = "Duplicate route ID."] ReactRouterNoDuplicateRouteId, #[doc = "Leaf route renders nothing."] ReactRouterNoEmptyLeafRoute,
    #[doc = "Absolute child path escapes its parent."] ReactRouterNoInvalidAbsoluteChildPath, #[doc = "Immutable route property returned from lazy."] ReactRouterNoInvalidLazyRouteProperties, #[doc = "Invalid splat route path."] ReactRouterNoInvalidSplatPath,
    #[doc = "Loader reads a request body."] ReactRouterNoLoaderRequestBody, #[doc = "Middleware consumes the outgoing response body."] ReactRouterNoMiddlewareResponseBodyConsumption, #[doc = "Multiple blockers in one component."] ReactRouterNoMultipleBlockers,
    #[doc = "Middleware continuation called twice."] ReactRouterNoMultipleMiddlewareNext, #[doc = "Search params updated multiple times."] ReactRouterNoMultipleSetSearchParamsInTick, #[doc = "navigate() called during render."] ReactRouterNoNavigateInRender,
    #[doc = "Router nested inside another router."] ReactRouterNoNestedRouter, #[doc = "redirect() inside try-catch."] ReactRouterNoRedirectInTryCatch, #[doc = "Route module has an environment suffix."] ReactRouterNoRouteModuleEnvironmentSuffix,
    #[doc = "Router created during render."] ReactRouterNoRouterInRender, #[doc = "Loader mutates session state."] ReactRouterNoSessionMutationInLoader, #[doc = "Cookie expiry is fixed at module load."] ReactRouterNoStaticCookieExpires,
    #[doc = "Search params mutated without navigation."] ReactRouterNoUnsynchronizedSearchParamsMutation, #[doc = "Error UI assumes loader data exists."] ReactRouterNoUseLoaderDataInErrorUi, #[doc = "Root route lacks an error boundary."] ReactRouterRequireRootErrorBoundary,
    #[doc = "Resource link intercepted as navigation."] ReactRouterResourceLinkRequiresReload, #[doc = "Transition drops a navigation promise."] ReactRouterReturnNavigationPromiseInTransition, #[doc = "Server middleware drops the Response."] ReactRouterServerMiddlewareReturnResponse,
    #[doc = "Session mutation is not committed."] ReactRouterSessionMutationRequiresCommit, #[doc = "Removed meta data field."] ReactRouterV8NoMetaDataField, #[doc = "Removed react-router-dom import."] ReactRouterV8NoReactRouterDomImport,
    #[doc = "Removed React Router future flag."] ReactRouterV8NoRemovedFutureFlags, #[doc = "Contradictory route object."] ReactRouterValidRouteObject, #[doc = "useSelector derives data inline."] ReduxUseselectorInlineDerivation,
    #[doc = "useSelector returns a new collection."] ReduxUseselectorReturnsNewCollection, #[doc = "calculateMetadata fetch ignores abortSignal."] RemotionCalculateMetadataFetchSignal, #[doc = "Randomness changes between rendered frames."] RemotionDeterministicRandomness,
    #[doc = "CSS animation is not frame-driven."] RemotionNoCssAnimation, #[doc = "CSS transition is not frame-driven."] RemotionNoCssTransition, #[doc = "CSS URL asset can flicker in Remotion."] RemotionNoCssUrlAssets,
    #[doc = "Module-scoped delayRender blocks every composition."] RemotionNoModuleScopeDelayRender, #[doc = "Native media element bypasses Remotion loading."] RemotionNoNativeMediaElements, #[doc = "Next.js Image can flicker in Remotion."] RemotionNoNextImage,
    #[doc = "delayRender handle is recreated during render."] RemotionStableDelayRenderHandle, #[doc = "Overly precise SVG path values."] RenderingSvgPrecision, #[doc = "Render method does not return."] RequireRenderReturn,
    #[doc = "Command item styled by presence-only state variant."] ShadcnCommandItemStateVariantRequiresValue, #[doc = "Raw control directly inside InputGroup."] ShadcnInputGroupNoRawControls, #[doc = "Tabs trigger is outside TabsList."] ShadcnTabsTriggerRequiresList,
    #[doc = "Non-transient custom prop on styled intrinsic element."] StyledComponentsNonTransientCustomPropOnIntrinsicElement, #[doc = "Form submit reloads the page around handleSubmit."] TanstackFormOnSubmitRequiresPreventDefault, #[doc = "Table data or columns recreated every render."] TanstackTableNoUnstableDataOrColumns,
    #[doc = "Measured virtual item without data-index."] TanstackVirtualMeasureElementRequiresDataIndex, #[doc = "Children on a void element."] VoidDomElementsNoChildren, #[doc = "Web Animation starts during render."] WaapiAnimationInRender,
    #[doc = "WritableSignal mutated inside Angular `effect()` instead of `computed()`."] AngularNoSignalWriteInEffect, #[doc = "RxJS `.subscribe()` without `takeUntilDestroyed()` or `ngOnDestroy` teardown."] AngularRxjsSubscribeRequiresTeardown, #[doc = "`@Component` decorator missing `changeDetection: ChangeDetectionStrategy.OnPush`."] AngularPreferOnPushChangeDetection,
    #[doc = "Unstable `@for (...; track)` expression using `$index` or raw object identity."] AngularForTrackNoIndex, #[doc = "Heavy side effects, HTTP requests, or subscriptions inside Angular `constructor()`."] AngularNoWorkInConstructor, #[doc = "Nested RxJS `.subscribe()` call instead of `switchMap` / `mergeMap` / `concatMap` / `exhaustMap`."] AngularNoNestedSubscribe,
    #[doc = "Direct DOM mutation on `ElementRef.nativeElement` instead of bindings or `Renderer2`."] AngularNoDirectNativeElementMutation, #[doc = "Unchecked `.unwrap()` or `.expect()` call in production Rust code."] RsNoUnwrapInProduction, #[doc = "Direct slice or `Vec` indexing `slice[idx]` without prior bounds guard."] RsNoUnguardedSliceIndex,
    #[doc = "Potentially lossy or sign-changing numeric `as` cast."] RsNoLossyNumericAsCast, #[doc = "`unsafe` block or `unsafe impl` missing a `// SAFETY:` invariant comment."] RsRequireSafetyCommentOnUnsafe, #[doc = "`std::mem::forget` or `core::mem::forget` call that leaks resources."] RsNoMemForget,
    #[doc = "Mutable default argument in function definition."] PyNoMutableDefaultArg, #[doc = "Broad or bare except block silently swallows exceptions."] PyNoSilentBroadExcept, #[doc = "File or database resource acquired without a with context manager."] PyRequireContextManagerForResource,
    #[doc = "Unguarded parse call or dictionary key indexing on untrusted input."] PyNoUnguardedParseOrKeyAccess, #[doc = "Naive datetime.now() or datetime.utcnow() call without explicit timezone."] PyRequireTimezoneAwareDatetime, #[doc = "Pydantic or dataclass field using mutable or runtime-call default instead of `default_factory`."] PyPydanticPreferDefaultFactory,
    #[doc = "FastAPI route handler missing both `response_model` and an explicit typed return annotation."] PyFastapiRequireResponseModel, #[doc = "State-mutating FastAPI route (`POST`/`PUT`/`PATCH`/`DELETE`) missing an authentication dependency."] PyFastapiMutatingRouteRequiresAuth, #[doc = "SQLAlchemy or Django ORM query executed inside a `for` or `while` loop (N+1 query hazard)."] PyOrmNoQueryInLoop,
    #[doc = "Raw f-string, `.format()`, `%`, or `+` SQL string interpolation passed to an execution sink."] PySecurityNoRawSqlInterpolation, #[doc = "Unsafe deserialization (`pickle.loads`, `yaml.load` without `SafeLoader`) or shell execution (`shell=True`, `eval`, `exec`, `os.system`)."] PySecurityNoUnsafeDeserializationOrShell, #[doc = "Synchronous blocking call inside an `async def` coroutine."] PyAsyncNoBlockingCall,
    #[doc = "Sequential `await` inside a `for` loop over independent coroutines."] PyAsyncNoSequentialAwaitInLoop, #[doc = "Coroutine function called without `await` or task scheduling."] PyAsyncNoUnawaitedCoroutine, #[doc = "`asyncio.create_task` or `loop.create_task` called without retaining a strong reference."] PyAsyncNoFireAndForgetTask,
    #[doc = "Constant `re.compile(...)` called inside a function, method, or loop instead of module scope."] PyPerfHoistRegex, #[doc = "Linear `in` membership check against a `list` inside a loop."] PyPerfNoLinearMembershipInLoop, #[doc = "Circular module import cycle across the Python package graph."] PyArchNoCircularImports,
    #[doc = "Public top-level Python symbol never imported or referenced across the package."] PyArchNoUnusedExports, #[doc = "SQLx query built with `format!(...)` string interpolation instead of `$1` / `?` `.bind(...)` parameters."] RsSqlxNoFormattedQueryString, #[doc = "SQLx query executed sequentially inside a `for`, `while`, or `loop` body (N+1 query hazard)."] RsSqlxNoQueryInLoop,
    #[doc = "Axum `State<...>` wrapping `Arc<Mutex<...>>` or contended `Mutex` state that serializes concurrent requests."] RsAxumNoContendedMutexState, #[doc = "Reactive signal write inside a Leptos/Dioxus effect (`create_effect`, `Effect::new`, `use_effect`) deriving state from another signal."] RsUiNoDerivedSignalInEffect, #[doc = "Function or method declaring 3 or more `bool` parameters (or 2+ consecutive `bool` parameters on public APIs)."] RsArchNoManyBooleanParams,
    #[doc = "`pub(crate)` item never referenced or imported by any other module or file in the crate."] RsArchNoUnusedPubCrateItems, #[doc = "Holding a `std::sync::MutexGuard` or `RwLock` guard across an `.await` point."] RsTokioNoStdLockAcrossAwait, #[doc = "Synchronous blocking call (`std::thread::sleep`, `std::fs`, `std::net`) inside an `async` context."] RsTokioNoBlockingInAsync,
    #[doc = "`tokio::sync::mpsc::unbounded_channel` used without bounded backpressure."] RsTokioPreferBoundedChannel, #[doc = "Heap allocation `.clone()` inside a hot `for`, `while`, or `loop` body."] RsPerfNoCloneInLoop, #[doc = "`Regex::new(...)` compiled repeatedly inside a function or loop instead of `std::sync::LazyLock`."] RsPerfHoistRegexToLazylock,
    #[doc = "`Vec::new()` followed by an unconditional `for` loop of `.push(...)` without `Vec::with_capacity`."] RsPerfPreferVecWithCapacity, #[doc = "Unnecessary `format!(...)` allocation on a plain literal or single string argument."] RsPerfNoUnnecessaryFormat, #[doc = "Binary or service entrypoint embeds domain logic, direct I/O, or rendering instead of thin adapter delegation."] ArchThinEntrypoint,
    #[doc = "Single module interleaves database/filesystem/network I/O with terminal or UI presentation."] ArchNoMixedIoAndPresentation, #[doc = "Module combines core domain type definitions with a large static data catalog."] ArchSeparateStaticCatalogFromTypes, #[doc = "Monolithic module combines unrelated domain symbol clusters and responsibilities."] ArchNoMixedDomainMonolith,
    #[doc = "Raw ANSI escape sequences or Unicode box-drawing literals constructed inline outside the terminal UI kit."] ArchNoInlineTerminalUiPrimitives, #[doc = "Multi-field struct, class, or object constructed repeatedly via boilerplate literals instead of a fluent builder."] ArchPreferFluentBuilder, #[doc = "Private helper function with identical normalized AST fingerprint duplicated across sibling modules."] ArchNoDuplicatedHelperLogic,
    #[doc = "Internal Rust submodule declared as `pub mod` when the crate root already re-exports its public API surface."] RsArchPreferPubCrateModules, #[doc = "Legacy `<dir>/mod.rs` directory module file used instead of modern `<dir>.rs` layout."] RsArchNoLegacyModRs, #[doc = "Loop-invariant OS environment or process query (`std::env::current_dir`, `temp_dir`, `var`) executed inside a loop or iterator closure."] RsPerfNoSyscallInLoop,
    #[doc = "`#[derive(Serialize)]` struct or enum contains an unannotated `HashSet` or `HashMap` field with non-deterministic iteration order."] RsNoUnorderedCollectionInSerialize, #[doc = "Signal read in a boolean/conditional test without calling the signal getter `()`."] AngularNoUncalledSignals, #[doc = "Paired `@Input() foo` and `@Output() fooChange` properties that can be replaced with `model()`."] AngularPreferSignalModel,
    #[doc = "Legacy `@Input()` or `BehaviorSubject` state where `input()` or `signal()` is preferred."] AngularPreferSignals, #[doc = "Conflicting `DoCheck` and `OnChanges` lifecycle hooks implemented on the same class."] AngularNoConflictingLifecycle, #[doc = "Angular lifecycle hook declared on an invalid decorator context (e.g. `ngOnInit` on `@Injectable` or `@Pipe`)."] AngularContextualLifecycle,
    #[doc = "Angular property/parameter decorator (`@Input`, `@Output`, `@ViewChild`, `@ContentChild`) used in an invalid class context."] AngularContextualDecorator, #[doc = "Angular lifecycle method marked `async`."] AngularNoAsyncLifecycleMethod, #[doc = "Direct imperative invocation of an Angular lifecycle hook (`this.ngOnInit()`)."] AngularNoLifecycleCall,
    #[doc = "Angular lifecycle hook declared as an instance arrow/function property instead of a prototype method."] AngularRequireLifecycleOnPrototype, #[doc = "Empty Angular lifecycle hook method body."] AngularNoEmptyLifecycleMethod, #[doc = "Class implements an Angular lifecycle hook method without declaring the corresponding lifecycle interface."] AngularUseLifecycleInterface,
    #[doc = "`@Pipe` class does not implement `PipeTransform`."] AngularUsePipeTransformInterface, #[doc = "`@Pipe` configured with `pure: false`."] AngularNoPipeImpure, #[doc = "`@Output` or `output()` named after a native DOM event (`click`, `change`, `focus`, `blur`, `submit`)."] AngularNoOutputNative,
    #[doc = "`@Output` or `output()` property prefixed with `on`."] AngularNoOutputOnPrefix, #[doc = "`@Component` `templateUrl` or `styleUrl`/`styleUrls` path missing a `./` or `../` relative prefix."] AngularRelativeUrlPrefix, #[doc = "`@Component`, `@Directive`, or `@Pipe` explicitly setting `standalone: false`."] AngularPreferStandalone,
    #[doc = "Constructor parameter dependency injection used instead of `inject()`."] AngularPreferInject, #[doc = "`@Injectable()` service missing `providedIn` scope metadata."] AngularUseInjectableProvidedIn, #[doc = "`@HostBinding` or `@HostListener` decorator used instead of the `host: { ... }` metadata property."] AngularPreferHostMetadataProperty,
    #[doc = "Duplicate identifier in `@Component`, `@Directive`, or `@NgModule` metadata array (`imports`, `providers`, `declarations`, `exports`)."] AngularNoDuplicatesInMetadataArrays, #[doc = "`forwardRef(...)` indirection used to resolve a dependency reference."] AngularNoForwardRef, #[doc = "`inputs: [...]` metadata property used in `@Component` or `@Directive`."] AngularNoInputsMetadataProperty,
    #[doc = "`outputs: [...]` metadata property used in `@Component` or `@Directive`."] AngularNoOutputsMetadataProperty, #[doc = "`queries: { ... }` metadata property used in `@Component` or `@Directive`."] AngularNoQueriesMetadataProperty, #[doc = "`@Output()` or `output()` class property not marked `readonly`."] AngularPreferOutputReadonly,
    #[doc = "`@Output()` initialized with a manual RxJS `Subject` instead of `EventEmitter` or `output()`."] AngularPreferOutputEmitterRef, #[doc = "`@Component` disabling style encapsulation via `ViewEncapsulation.None`."] AngularUseComponentViewEncapsulation, #[doc = "`@Attribute(...)` constructor parameter decorator used instead of `input()` or `@Input()`."] AngularNoAttributeDecorator,
    #[doc = "`@Component` inline `template` or `styles` declaration exceeds maximum line threshold."] AngularComponentMaxInlineDeclarations, #[doc = "`$any(...)` type-cast call inside an Angular template expression."] AngularTemplateNoAny, #[doc = "`<img>`, `<area>`, `<input type=\"image\">`, or `<object>` in an Angular template missing accessible `alt` text."] AngularTemplateAltText,
    #[doc = "`(click)` binding on a non-interactive element in an Angular template without keyboard event support."] AngularTemplateClickEventsHaveKeyEvents, #[doc = "`(mouseover)` or `(mouseout)` binding in an Angular template without corresponding `(focus)` or `(blur)`."] AngularTemplateMouseEventsHaveKeyEvents, #[doc = "Heading (`<h1>`–`<h6>`) or anchor (`<a>`) element in an Angular template with no accessible content."] AngularTemplateElementsHaveContent,
    #[doc = "Interactive role and event binding on a non-interactive Angular template element missing `tabindex`."] AngularTemplateInteractiveSupportsFocus, #[doc = "`scope` or `[attr.scope]` attribute placed on a non-`<th>` element or given an invalid scope value in an Angular template."] AngularTemplateTableScope, #[doc = "Invalid or misspelled `aria-*` or `[attr.aria-*]` attribute in an Angular template."] AngularTemplateValidAria,
    #[doc = "NgRx `createEffect` pipeline returning multiple actions from a single mapping operator."] NgrxNoMultipleActionsInEffects, #[doc = "NgRx effect combining the legacy `@Effect()` decorator with `createEffect(...)`."] NgrxNoEffectDecoratorAndCreator, #[doc = "NgRx `createEffect` listening to `ofType(action)` and re-dispatching the same action cyclically."] NgrxNoCyclicActionCreators,
    #[doc = "NgRx `Store<T>` injected with a generic global state type parameter."] NgrxNoTypedGlobalStore, #[doc = "NgRx `on(action, (state, action) => ...)` reducer handler missing an explicit return type annotation."] NgrxOnFunctionExplicitReturnType, #[doc = "NgRx `store.pipe(select(...))` or string-literal `store.select('...')` used instead of `store.select(selector)` / `store.selectSignal(selector)`."] NgrxSelectStyle,
    #[doc = "Conflicting Angular Material theme mixins or mutually exclusive Material button/directive selectors."] AngularMaterialNoConflictingMixins, #[doc = "Python function or method exceeds cyclomatic (`> 15`) or cognitive (`> 25`) complexity threshold."] PyZenComplexFunction, #[doc = "Python function or method control-flow nesting depth exceeds `5`."] PyZenDeepNesting,
    #[doc = "Python function or method body exceeds `75` lines."] PyZenLongFunction, #[doc = "Python function or method declares more than `10` parameters (excluding `self`/`cls` and `__init__`)."] PyZenTooManyParams, #[doc = "Python `class` definition declares more than `20` direct methods."] PyZenLargeClass,
    #[doc = "Python source line chains multiple semicolon-separated statements."] PyZenNoDenseSemicolonStatements, #[doc = "Wildcard `from module import *` statement outside `__init__.py`."] PyNoWildcardImport, #[doc = "Python `requests` or `httpx` HTTP call missing a `timeout` argument."] PySecurityHttpRequestRequiresTimeout,
    #[doc = "Python HTTP client or SSL context disabling TLS certificate verification (`verify=False`, `ssl._create_unverified_context`)."] PySecurityNoDisabledTlsVerify, #[doc = "Weak cryptographic hash (`md5`, `sha1`), non-CSPRNG `random.*` for secrets/tokens, or non-constant-time secret comparison (`==`)."] PySecurityNoWeakCryptoOrRandom, #[doc = "Unsafe XML parser vulnerable to XXE or unvalidated `tarfile`/`zipfile.extractall()` archive extraction."] PySecurityNoXxeOrUnsafeArchive,
    #[doc = "Hardcoded password/secret/token literal or insecure `/tmp` path in production Python code."] PySecurityNoHardcodedSecretOrTmp, #[doc = "Typed Python library package missing a PEP 561 `py.typed` marker file."] PyStructureMissingPyTyped, #[doc = "Python package has low type-annotation coverage across production modules (`< 50%`)."] PyStructureLowTypeHintCoverage,
    #[doc = "`tokio::task::block_in_place` called on a `current_thread` Tokio runtime or single-threaded `#[tokio::test]`."] RsTokioNoBlockInPlaceOnCurrentThread, #[doc = "`futures::executor::block_on` or `tokio::runtime::Runtime::block_on` / `Handle::block_on` called inside an `async` context."] RsAsyncNoBlockOnInAsync, #[doc = "`reqwest` client builder disabling TLS certificate or hostname verification (`danger_accept_invalid_certs(true)`)."] RsSecurityNoDisabledTlsVerification,
    #[doc = "`std::process::Command` executing a dynamically constructed program path or formatted `-c` / `/C` shell script."] RsSecurityNoDynamicShellCommand, #[doc = "`reqwest` response body read (`.json()`, `.text()`, `.bytes()`) without checking `.error_for_status()` or `.status()`."] RsHttpNoUncheckedResponseStatus, #[doc = "Secret environment variable read (`std::env::var`) falling back to a hardcoded literal or empty default via `.unwrap_or*`."] RsSecurityNoSecretEnvFallback,
    #[doc = "Permissive CORS configuration (`CorsLayer::very_permissive()`, `Cors::permissive()`, or `allow_credentials(true)` with wildcard/mirrored origin)."] RsSecurityNoPermissiveCors, #[doc = "Authentication or session `Cookie` built with `.http_only(false)`."] RsSecurityNoInsecureAuthCookie, #[doc = "`jsonwebtoken` validation disabling signature verification (`insecure_disable_signature_validation`, `dangerous::insecure_decode`)."] RsSecurityNoDisabledJwtValidation,
    #[doc = "Multiple incompatible major versions of the same crate resolved in `Cargo.lock`."] RsCargoDuplicateMajorVersions, #[doc = "Binary Cargo package missing a committed `Cargo.lock` at the workspace root."] RsCargoMissingLockfile, #[doc = "Cargo `path` dependency resolving outside the workspace root directory."] RsCargoPathDepOutsideWorkspace,
    #[doc = "`[lints.clippy]` or `[workspace.lints.clippy]` manifest table setting an active catalogued lint to `\"allow\"`."] RsCargoPermissiveLintTable, #[doc = "`.cargo/config.toml` `rustflags` disabling lints (`-A warnings`, `--cap-lints allow`) or overflow checks (`overflow-checks=off`)."] RsCargoPermissiveRustflags, #[doc = "`[profile.release]` enabling full debug symbols without `strip`."] RsCargoReleaseDebugSymbols,
    #[doc = "Binary workspace root `Cargo.toml` missing `overflow-checks = true` under `[profile.release]`."] RsCargoUncheckedReleaseOverflow, #[doc = "Non-optional `[dependencies]` entry in `Cargo.toml` never referenced in package source files."] RsCargoUnusedDependency, #[doc = "Non-optional `[dependencies]` entry referenced only in tests, benches, or examples instead of `[dev-dependencies]`."] RsCargoTestOnlyDependency,
    #[doc = "Registry dependency in `Cargo.toml` using an unbounded wildcard `\"*\"` version requirement."] RsCargoUnboundedWildcardDependency, #[doc = "Git dependency in `Cargo.toml` not pinned to a full 40-character commit SHA `rev`."] RsCargoUnpinnedGitDependency, #[doc = "File-wide or module-wide inner `#![allow(...)]` attribute silencing lints across an entire scope."] RsStructureCrateLevelAllow,
    #[doc = "`#[allow(...)]` attribute missing a `reason = \"...\"` justification argument."] RsStructureUnreasonedAllow, #[doc = "Item stacking multiple `#[allow(...)]` attributes or silencing 4 or more lints in one attribute."] RsStructureStackedAllow, #[doc = "Rust function or method exceeding cyclomatic (`>= 20`) or cognitive (`>= 25`) complexity threshold."] RsStructureComplexFunction,
    #[doc = "Rust file (`>= 1000` lines), `impl`/`mod` block (`>= 500` lines), or function (`>= 150` lines) exceeding size budget."] RsStructureOversizedUnit, #[doc = "`.rs` source file under `src/` not reached by any `mod` declaration, `include!`, or `build.rs`."] RsStructureOrphanModuleFile, #[doc = "Declared Cargo feature in `[features]` never read by `cfg(feature = \"...\")`, or `cfg(feature = \"...\")` naming an undeclared feature."] RsStructureUnreferencedFeature,
    #[doc = "Near-duplicate Rust function bodies with normalized AST subtree Sørensen-Dice similarity `>= 80%`."] RsStructureNearDuplicateFunction, #[doc = "`RefCell::borrow()` or `RefCell::borrow_mut()` guard held across an `.await` point."] RsNoAwaitHoldingRefcell, #[doc = "`panic!`, `todo!`, `unimplemented!`, or `std::process::exit` in production Rust code."] RsNoPanicOrTodoInProduction,
    #[doc = "Leftover `dbg!` macro in production code, or `println!`/`eprintln!` in a library crate."] RsNoDbgOrPrintInLibrary, #[doc = "World-writable file permissions set via `Permissions::set_readonly(false)` or `from_mode(0o777)`."] RsSecurityNoWorldWritablePermissions, #[doc = "Spawned `std::process::Command::spawn()` child process handle dropped without calling `.wait()` or `.wait_with_output()`."] RsNoZombieChildProcess,
    #[doc = "`std::mem::transmute` called without explicit source and destination turbofish type annotations `::<Src, Dst>`."] RsNoTransmuteWithoutTypeAnnotations, #[doc = "`pub unsafe fn` missing a `# Safety` documentation section."] RsRequireSafetyDocOnPubUnsafeFn, #[doc = "GitHub Actions workflow vulnerability (`pull_request_target` untrusted checkout, `${{ github.event.* }}` shell injection, or secret in build step)."] CiWorkflowSecurityRisk,
    #[doc = "Electron, Tauri, or mobile WebView bridge misconfiguration (`nodeIntegration: true`, `contextIsolation: false`, unvalidated `senderFrame` or `openExternal`)."] ElectronWebviewBridgeRisk, #[doc = "Password-reset, OAuth callback, or absolute URL constructed from an unvalidated `Host` or `X-Forwarded-Host` header."] UntrustedHostHeaderOrigin, #[doc = "Authenticated route reading cookies/session/authorization headers while setting `Cache-Control: public` or `s-maxage`."] PrivateResponsePublicCache,
    #[doc = "Raw client `messages` passed to an LLM without role filtering, unbounded tool loop missing `maxSteps`, or MCP tool args flowing into dangerous sinks."] LlmPromptRoleAndToolSinkRisk, #[doc = "Server route using `SUPABASE_SERVICE_ROLE_KEY` to query or mutate tables with request inputs without an explicit tenant/user `.eq(...)` filter."] SupabaseServiceRoleUnscopedQuery,
}

/// Static catalog metadata for a registered diagnostic rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RuleMetadata {
    /// Typed [`RuleId`] variant.
    pub id: RuleId,
    /// Canonical short identifier (`"no-derived-state"`).
    pub canonical_id: &'static str,
    /// Qualified identifier (`"dotore/no-derived-state"`).
    pub qualified_key: &'static str,
    /// Legacy plugin-prefixed aliases (`"effect/no-derived-state"`, `"react/jsx-key"`, etc.).
    pub legacy_aliases: &'static [&'static str],
    /// Short human-readable headline.
    pub title: &'static str,
    /// Rule category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`).
    pub category: RuleCategory,
    /// Default severity (`Error` or `Warning`).
    pub default_severity: RuleSeverity,
    /// Whether the rule is enabled by default in standard scans.
    pub default_enabled: bool,
    /// Whether the rule was originally ported from an external plugin (governed by `customRulesOnly`).
    pub originally_external: bool,
    /// Behavioral tags attached to this rule.
    pub tags: &'static [RuleTag],
    /// **Capability Gate** activation predicate.
    pub capability_gate: CapabilityPredicate,
    /// **Contextual Owner** policy for `--scope contextual` diff filtering.
    pub contextual_owner: ContextualOwnerPolicy,
    /// Default **Prescription Tier** (`Autofix`, `Surgical`, `Refactor`).
    pub default_tier: PrescriptionTier,
    /// Official documentation URL.
    pub docs_url: &'static str,
    /// Compiled-in remediation recipe (Markdown transformation instructions).
    pub recipe_markdown: &'static str,
}

#[expect(
    clippy::too_many_arguments,
    reason = "Static rule registry constructor binds all 15 metadata fields in a single compact table entry"
)]
pub(crate) const fn rule_meta(
    id: RuleId,
    canonical_id: &'static str,
    qualified_key: &'static str,
    legacy_aliases: &'static [&'static str],
    title: &'static str,
    category: RuleCategory,
    default_severity: RuleSeverity,
    default_enabled: bool,
    originally_external: bool,
    tags: &'static [RuleTag],
    capability_gate: CapabilityPredicate,
    contextual_owner: ContextualOwnerPolicy,
    default_tier: PrescriptionTier,
    docs_url: &'static str,
    recipe_markdown: &'static str,
) -> RuleMetadata {
    RuleMetadata {
        id,
        canonical_id,
        qualified_key,
        legacy_aliases,
        title,
        category,
        default_severity,
        default_enabled,
        originally_external,
        tags,
        capability_gate,
        contextual_owner,
        default_tier,
        docs_url,
        recipe_markdown,
    }
}

/// Returns the static catalog of all registered [`RuleMetadata`] entries.
#[must_use]
pub const fn rule_registry() -> &'static [RuleMetadata] {
    super::catalog::RULE_REGISTRY
}

impl RuleId {
    /// Returns the static [`RuleMetadata`] for this rule.
    #[must_use]
    pub const fn metadata(self) -> &'static RuleMetadata {
        let idx = self as usize;
        assert!(idx < super::catalog::RULE_REGISTRY_ARRAY.len());
        &super::catalog::RULE_REGISTRY_ARRAY[idx]
    }

    /// Returns the kebab-case CLI / config rule identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.metadata().canonical_id
    }

    /// Official documentation URL for this rule.
    #[must_use]
    pub const fn docs_url(self) -> &'static str {
        self.metadata().docs_url
    }

    /// Parses a rule identifier from its canonical short ID (`"no-derived-state"`),
    /// qualified key (`"dotore/no-derived-state"`), or any legacy alias (`"effect/no-derived-state"`, `"react/jsx-key"`).
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return None;
        }
        let without_prefix = trimmed
            .strip_prefix("dotore/")
            .or_else(|| trimmed.strip_prefix("dotore::"))
            .unwrap_or(trimmed);
        if without_prefix
            .strip_prefix("radon/CC")
            .or_else(|| without_prefix.strip_prefix("radon/cc"))
            .is_some_and(|rest| rest.is_empty() || rest.bytes().all(|b| b.is_ascii_digit()))
        {
            return Some(Self::PyZenComplexFunction);
        }
        let without_clippy = without_prefix.strip_prefix("clippy::");
        for meta in super::catalog::RULE_REGISTRY {
            if meta.canonical_id == without_prefix
                || meta.qualified_key == trimmed
                || meta.legacy_aliases.contains(&trimmed)
                || meta.legacy_aliases.contains(&without_prefix)
                || without_clippy.is_some_and(|c| meta.legacy_aliases.contains(&c))
            {
                return Some(meta.id);
            }
        }
        if without_prefix.contains('_') {
            let kebab = without_prefix.replace('_', "-");
            for meta in super::catalog::RULE_REGISTRY {
                if meta.canonical_id == kebab {
                    return Some(meta.id);
                }
            }
        }
        None
    }

    /// Returns `true` if `candidate` resolves to `self` via canonical ID, qualified key, or legacy alias.
    #[must_use]
    pub fn matches_key(self, candidate: &str) -> bool {
        Self::parse(candidate) == Some(self)
    }

    /// Returns `true` if this rule belongs to the Architecture, Separation of Concerns (SoC),
    /// module visibility/layout, or structural reuse rule suite.
    #[must_use]
    pub const fn is_architecture_soc_or_reuse_rule(self) -> bool {
        matches!(
            self,
            Self::ArchThinEntrypoint
                | Self::ArchNoMixedIoAndPresentation
                | Self::ArchSeparateStaticCatalogFromTypes
                | Self::ArchNoMixedDomainMonolith
                | Self::ArchNoInlineTerminalUiPrimitives
                | Self::ArchPreferFluentBuilder
                | Self::ArchNoDuplicatedHelperLogic
                | Self::RsArchPreferPubCrateModules
                | Self::RsArchNoLegacyModRs
                | Self::DuplicateJsxSubtree
                | Self::CircularDependency
                | Self::PyArchNoCircularImports
                | Self::RsArchNoUnusedPubCrateItems
                | Self::RsStructureNearDuplicateFunction
                | Self::RsStructureOrphanModuleFile
                | Self::RsStructureOversizedUnit
                | Self::RsStructureComplexFunction
                | Self::PyStructureMissingPyTyped
                | Self::PyStructureLowTypeHintCoverage
        )
    }
}

