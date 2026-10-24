//! Domain types for the unified rule registry, metadata, categories, tags,
//! **Capability Gate** predicates, **Contextual Owner** policies, **Prescription Tiers**,
//! and autofix patches.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    config::CapabilityPredicate,
    ir::{ByteSpan, ResolvedCallerSite, SourceLoc},
};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleId {
    /// Updating state from props or state inside `useEffect`.
    NoDerivedState,
    /// Chaining state updates across one or multiple `useEffect`s.
    NoChainStateUpdates,
    /// Using state/props + `useEffect` as an event handler.
    NoEventHandler,
    /// Adjusting partial state when a prop changes.
    NoAdjustStateOnPropChange,
    /// Resetting all state when a prop changes instead of passing `key`.
    NoResetAllStateOnPropChange,
    /// Calling a parent callback prop with live local state inside `useEffect`.
    NoPassLiveStateToParent,
    /// Calling a parent callback prop with fetched/hook data inside `useEffect`.
    NoPassDataToParent,
    /// Subscribing to an external store in `useEffect` instead of `useSyncExternalStore`.
    NoExternalStoreSubscription,
    /// Initializing state synchronously in a mount-only `useEffect(..., [])`.
    NoInitializeState,
    /// Fetching data inside `useEffect` (with or without cancellation cleanup).
    NoFetchInEffect,
    /// Missing `key` prop on elements in an array or iterator.
    JsxKey,
    /// Using array index as `key` prop in `.map()`.
    NoArrayIndexAsKey,
    /// Referencing an undefined JSX component identifier.
    JsxNoUndef,
    /// Missing or unnecessary dependencies in React hooks (`useEffect`, `useMemo`, `useCallback`).
    ExhaustiveDeps,
    /// Exporting non-component values alongside React components in Fast Refresh modules.
    OnlyExportComponents,
    /// Mutating `useState` value binding directly instead of calling the state setter.
    NoDirectMutationState,
    /// Passing a freshly allocated object literal as a JSX prop (disabled when React Compiler is active).
    JsxNoNewObjectAsProp,
    /// `<img>` element missing accessible `alt` attribute.
    AltText,
    /// Animation / motion usage without reduced-motion guard.
    RequireReducedMotion,
    /// Vague button label (`"Click here"`, `"Submit"`) flagged in design audit.
    DesignNoVagueButtonLabel,
    /// Using `dangerouslySetInnerHTML` on a JSX element.
    NoDanger,
    /// `"use server"` action missing an authentication guard.
    ServerAuthActions,
    /// `await` inside a `for`/`while` loop instead of `Promise.all`.
    AsyncAwaitInLoop,
    /// Passing render-prop children function to a component (skipped on library entrypoints).
    NoRenderPropChildren,
    /// Unreferenced source file in the project module graph.
    UnusedFile,
    /// Exported value symbol with no importer in the project module graph.
    UnusedExport,
    /// Exported TypeScript type or interface with no importer in the project module graph.
    UnusedType,
    /// Declared `dependencies` package in `package.json` with no discovered usage.
    UnusedDependency,
    /// Declared `devDependencies` package in `package.json` with no discovered usage.
    UnusedDevDependency,
    /// Runtime import cycle across modules in a strongly connected component.
    CircularDependency,
    /// Structurally duplicated JSX subtree across components or files.
    DuplicateJsxSubtree,
    /// Raw `<img>` element in Next.js instead of `next/image`.
    NextjsNoImgElement,
    /// Raw text node outside `<Text>` or configured `textComponents` in React Native.
    RnNoRawText,
    /// Dynamic `process.env[key]` access in Expo instead of static `process.env.EXPO_PUBLIC_*`.
    ExpoNoNonInlinedEnv,
    /// `useQuery` with a `queryFn` that returns `undefined` / `void`.
    QueryNoVoidQueryFn,
    /// TanStack Start `createServerFn` handler without `.validator(...)` input validation.
    TanstackStartServerFnValidateInput,
    /// Allocating Three.js geometry inside `requestAnimationFrame`.
    ThreeNoGeometryInFrameLoop,
    /// Unbounded device pixel ratio.
    R3fCapDevicePixelRatio,
    /// Too many shadow-casting point lights.
    R3fLimitShadowedPointLights,
    /// Clock advanced inside useFrame.
    R3fNoAdvancingClockInUseFrame,
    /// Allocation inside an R3F pointer-move handler.
    R3fNoAllocationInPointerMove,
    /// Async useFrame callback.
    R3fNoAsyncUseFrame,
    /// Three.js clone inside useFrame.
    R3fNoCloneInUseFrame,
    /// R3F shader precompilation inside useFrame.
    R3fNoCompileInUseFrame,
    /// useThree selector reads a mutable Three.js field.
    R3fNoDeepUseThreeSelector,
    /// Disposal of a cached R3F loader asset.
    R3fNoDisposeLoaderCache,
    /// Primitive object mounted twice.
    R3fNoDuplicatePrimitiveObject,
    /// R3F catalogue extension during render.
    R3fNoExtendInRender,
    /// Whole Three.js namespace registered with R3F.
    R3fNoExtendThreeNamespace,
    /// Fresh R3F portal container.
    R3fNoFreshPortalContainer,
    /// Fresh useThree selector result.
    R3fNoFreshUseThreeSelector,
    /// PBR prop ignored by R3F meshBasicMaterial.
    R3fNoIgnoredBasicMaterialProperties,
    /// R3F GPU renderer ignores line width.
    R3fNoIgnoredLinewidth,
    /// Imperative attachment of an R3F-managed ref.
    R3fNoImperativeAttachOfManagedRef,
    /// Inline primitive object.
    R3fNoInlinePrimitiveObject,
    /// Inline R3F resource prop.
    R3fNoInlineResourceProp,
    /// Private R3F import.
    R3fNoInternalImports,
    /// Manual resize loop for an R3F-owned renderer.
    R3fNoManualCanvasResize,
    /// Mutation of a cached R3F loader asset.
    R3fNoMutateLoaderCache,
    /// R3F uniform prop source mutated after being copied.
    R3fNoMutateUniformPropSourceInUseFrame,
    /// Mutation of shared R3F pointer-event data.
    R3fNoMutatingPointerEventData,
    /// Ignored normalization on R3F float attribute.
    R3fNoNormalizedFloatBufferAttribute,
    /// Nullish R3F loader input.
    R3fNoNullLoaderInput,
    /// Pointer capture called on an R3F scene object.
    R3fNoObjectPointerCapture,
    /// Competing animation loop alongside useFrame.
    R3fNoRecursiveRafWithUseFrame,
    /// R3F shader configuration mutates every frame.
    R3fNoShaderConfigurationMutationInUseFrame,
    /// R3F light cannot cast shadows.
    R3fNoShadowsOnUnsupportedLight,
    /// React state update inside an R3F pointer-move handler.
    R3fNoStateInPointerMove,
    /// React state update inside useFrame.
    R3fNoStateInUseFrame,
    /// Synchronous readback inside useFrame.
    R3fNoSyncReadbackInUseFrame,
    /// Unstable R3F constructor args.
    R3fNoUnstableArgs,
    /// Dependency array passed to useFrame.
    R3fNoUseFrameDependencyArray,
    /// Per-instance CPU transform animation in R3F useFrame.
    R3fPreferGpuInstancedAnimation,
    /// Per-vertex CPU animation in R3F useFrame.
    R3fPreferGpuPositionAnimation,
    /// Repeated R3F meshes use separate draw calls.
    R3fPreferInstancedMesh,
    /// Imperative Three.js loader in a React effect.
    R3fPreferUseLoader,
    /// R3F animation mixer is never advanced.
    R3fRequireAnimationMixerUpdate,
    /// R3F changed data texture is not marked for upload.
    R3fRequireDataTextureUpdate,
    /// R3F per-frame buffer upload keeps static usage.
    R3fRequireDynamicBufferUsage,
    /// Metal R3F material has no environment.
    R3fRequireEnvironmentForMetal,
    /// Frame-rate-dependent animation.
    R3fRequireFrameDelta,
    /// Unreleased global R3F render-loop effect.
    R3fRequireGlobalEffectCleanup,
    /// Instanced mesh buffer is not marked for upload.
    R3fRequireInstancedBufferUpdate,
    /// R3F PBR material has no lighting source.
    R3fRequireLightingForPbr,
    /// Normal-mapped R3F geometry has no normals.
    R3fRequireLitMaterialNormals,
    /// Locally owned Three.js texture is not disposed.
    R3fRequireOwnedTextureCleanup,
    /// R3F position buffer is not marked for upload.
    R3fRequirePositionBufferUpdate,
    /// Missing camera projection-matrix update.
    R3fRequireProjectionMatrixUpdate,
    /// R3F renderer leaves an offscreen target bound.
    R3fRequireRenderTargetReset,
    /// Positive useFrame priority without a render.
    R3fRequireRenderWithPositivePriority,
    /// R3F root without unmount cleanup.
    R3fRequireRootUnmount,
    /// R3F shadow caster without Canvas shadow maps.
    R3fRequireShadowsEnabled,
    /// R3F material opacity is ignored.
    R3fRequireTransparentForOpacity,
    /// Mapped R3F mesh geometry has no UVs.
    R3fRequireUvForTextureMap,
    /// R3F texture repeat without repeat wrapping.
    R3fTextureRepeatRequiresWrapping,
    /// R3F buffer attribute has a partial final item.
    R3fValidBufferAttributeArrayLength,
    /// Invalid R3F buffer attribute item size.
    R3fValidBufferAttributeItemSize,
    /// R3F fog has invalid range parameters.
    R3fValidFogParameters,
    /// R3F material opacity outside its normalized range.
    R3fValidMaterialOpacity,
    /// Invalid R3F orthographic camera.
    R3fValidOrthographicCamera,
    /// R3F PBR material factor outside its normalized range.
    R3fValidPbrMaterialProperties,
    /// Invalid R3F perspective camera.
    R3fValidPerspectiveCamera,
    /// Invalid R3F physical material property.
    R3fValidPhysicalMaterialProperties,
    /// Invalid R3F raycaster distance range.
    R3fValidRaycasterRange,
    /// Invalid R3F shadow map size.
    R3fValidShadowMapSize,
    /// Invalid R3F spotlight cone.
    R3fValidSpotLightProperties,
    /// R3F texture has an incompatible color space.
    R3fValidTextureColorSpace,
    /// Incompatible R3F Canvas renderer prop.
    R3fWebgpuCanvasPropCompatibility,
    /// WebGPU root reads deprecated gl state.
    R3fWebgpuNoGlState,
    /// R3F WebGPU high precision conflicts with instanced meshes.
    R3fWebgpuNoHighPrecisionInstancing,
    /// JavaScript branch reads a TSL uniform value.
    R3fWebgpuNoJsUniformBranch,
    /// Legacy EffectComposer inside an R3F WebGPU Canvas.
    R3fWebgpuNoLegacyEffectComposer,
    /// Legacy shader material API inside an R3F WebGPU Canvas.
    R3fWebgpuNoLegacyMaterialApi,
    /// Unregistered WebGPU pipeline pass.
    R3fWebgpuNoUnregisteredPipelinePass,
    /// R3F WebGPU factory skips asynchronous initialization.
    R3fWebgpuRequireAsyncInit,
    /// Unbounded Three.js device pixel ratio.
    ThreeCapDevicePixelRatio,
    /// Postprocessing pass follows OutputPass.
    ThreeEffectComposerOutputPassLast,
    /// EffectComposer size is stale after renderer resize.
    ThreeEffectComposerRequireSizeOnResize,
    /// GPU computation initialization error is ignored.
    ThreeGpuComputationHandleInitError,
    /// GPU computation runs before initialization.
    ThreeGpuComputationRequireInitBeforeCompute,
    /// GPU computation variable has an invalid shader name.
    ThreeGpuComputationValidVariableName,
    /// Too many shadow-casting Three.js point lights.
    ThreeLimitShadowedPointLights,
    /// Three.js allocation inside pointer-move handler.
    ThreeNoAllocationInPointerMove,
    /// Async Three.js animation callback.
    ThreeNoAsyncAnimationLoop,
    /// Three.js clone inside animation loop.
    ThreeNoCloneInAnimationLoop,
    /// Three.js shader precompilation inside animation loop.
    ThreeNoCompileInAnimationLoop,
    /// PBR property ignored by Three.js MeshBasicMaterial.
    ThreeNoIgnoredBasicMaterialProperties,
    /// Three.js GPU renderer ignores line width.
    ThreeNoIgnoredLinewidth,
    /// Material recompiled inside animation loop.
    ThreeNoMaterialRecompileInAnimationLoop,
    /// Allocation inside Three.js animation loop.
    ThreeNoNewInAnimationLoop,
    /// Ignored normalization on Three.js float attribute.
    ThreeNoNormalizedFloatBufferAttribute,
    /// Three.js object constructed during React render.
    ThreeNoObjectConstructionInRender,
    /// Redundant uniformsNeedUpdate inside animation loop.
    ThreeNoRedundantUniformsNeedUpdate,
    /// Shader configuration mutates every animation frame.
    ThreeNoShaderConfigurationMutationInAnimationLoop,
    /// Three.js light cannot cast shadows.
    ThreeNoShadowsOnUnsupportedLight,
    /// React state update inside Three.js animation loop.
    ThreeNoStateInAnimationLoop,
    /// React state update inside Three.js pointer-move handler.
    ThreeNoStateInPointerMove,
    /// Synchronous GPU readback in Three.js loop.
    ThreeNoSyncReadbackInAnimationLoop,
    /// Renderer resized unconditionally every frame.
    ThreeNoUnconditionalRendererResizeInAnimationLoop,
    /// onBeforeCompile variant lacks a program cache key.
    ThreeOnBeforeCompileRequireProgramCacheKey,
    /// Per-instance CPU transform animation in a Three.js loop.
    ThreePreferGpuInstancedAnimation,
    /// Per-vertex CPU animation in a Three.js frame loop.
    ThreePreferGpuPositionAnimation,
    /// Repeated Three.js meshes use separate draw calls.
    ThreePreferInstancedMesh,
    /// Three.js renderer uses manual animation frames.
    ThreePreferSetAnimationLoop,
    /// Raw fragment shader lacks float precision.
    ThreeRawShaderRequireFragmentFloatPrecision,
    /// Raw shader uses GLSL 3 syntax without GLSL3.
    ThreeRawShaderRequireGlsl3Version,
    /// Unreleased Three.js animation mixer actions.
    ThreeRequireAnimationMixerCleanup,
    /// Three.js animation mixer is never advanced.
    ThreeRequireAnimationMixerUpdate,
    /// Three.js resize leaves camera aspect stale.
    ThreeRequireCameraAspectOnResize,
    /// Undisposed imperative Three.js controls.
    ThreeRequireControlsCleanup,
    /// Three.js controls require per-frame updates.
    ThreeRequireControlsUpdate,
    /// Changed data texture is not marked for upload.
    ThreeRequireDataTextureUpdate,
    /// Per-frame buffer upload keeps static usage.
    ThreeRequireDynamicBufferUsage,
    /// Metal Three.js material has no environment.
    ThreeRequireEnvironmentForMetal,
    /// Frame-rate-dependent Three.js animation.
    ThreeRequireFrameDelta,
    /// Undisposed Three.js GPU computation renderer.
    ThreeRequireGpuComputationCleanup,
    /// Three.js instanced mesh buffer is not marked for upload.
    ThreeRequireInstancedBufferUpdate,
    /// KTX2Loader used before renderer support detection.
    ThreeRequireKtx2DetectSupport,
    /// Three.js PBR material has no lighting source.
    ThreeRequireLightingForPbr,
    /// Normal-mapped Three.js geometry has no normals.
    ThreeRequireLitMaterialNormals,
    /// Three.js asset load has no local error path.
    ThreeRequireLoaderErrorHandling,
    /// Locally owned Three.js geometry is not disposed.
    ThreeRequireOwnedGeometryCleanup,
    /// Locally owned Three.js material is not disposed.
    ThreeRequireOwnedMaterialCleanup,
    /// Locally owned Three.js texture is not disposed.
    ThreeRequireOwnedTextureCleanup,
    /// Three.js position buffer is not marked for upload.
    ThreeRequirePositionBufferUpdate,
    /// Undisposed Three.js postprocessing resource.
    ThreeRequirePostprocessingCleanup,
    /// Missing Three.js camera projection-matrix update.
    ThreeRequireProjectionMatrixUpdate,
    /// Three.js animation loop never renders.
    ThreeRequireRenderInAnimationLoop,
    /// Undisposed Three.js render target.
    ThreeRequireRenderTargetCleanup,
    /// Three.js renderer leaves an offscreen target bound.
    ThreeRequireRenderTargetReset,
    /// Undisposed Three.js renderer.
    ThreeRequireRendererCleanup,
    /// Three.js renderer canvas is never attached to the DOM.
    ThreeRequireRendererDomAttachment,
    /// Three.js renderer drawing buffer is never sized.
    ThreeRequireRendererSize,
    /// Three.js shadow caster without renderer shadow maps.
    ThreeRequireShadowsEnabled,
    /// Three.js texture wrapping changes without re-upload.
    ThreeRequireTextureUpdateAfterWrappingChange,
    /// Three.js material opacity is ignored.
    ThreeRequireTransparentForOpacity,
    /// Mapped Three.js mesh geometry has no UVs.
    ThreeRequireUvForTextureMap,
    /// Undisposed Three.js worker-backed loader.
    ThreeRequireWorkerLoaderCleanup,
    /// Shader uses a constant out-of-bounds index.
    ThreeShaderNoConstantOutOfBoundsIndex,
    /// Shader derivative runs in non-uniform control flow.
    ThreeShaderNoDerivativesInNonuniformFlow,
    /// GLSL 3 shader uses an unavailable GLSL 1 symbol.
    ThreeShaderNoGlsl1SyntaxWithGlsl3,
    /// Shader uses invalid clamp bounds.
    ThreeShaderNoInvalidClampBounds,
    /// Shader uses invalid constant bit operations.
    ThreeShaderNoInvalidConstantBitOperations,
    /// Shader uses invalid constant math.
    ThreeShaderNoInvalidConstantMath,
    /// Shader uses invalid smoothstep edges.
    ThreeShaderNoInvalidSmoothstepEdges,
    /// Shader inverts a uniform matrix per invocation.
    ThreeShaderNoInverseOfUniform,
    /// ShaderMaterial redeclares a Three.js builtin.
    ThreeShaderNoRedeclaredBuiltins,
    /// Shader redundantly writes fragment depth.
    ThreeShaderNoRedundantFragDepth,
    /// Shader declares a reserved GLSL identifier.
    ThreeShaderNoReservedIdentifiers,
    /// Three shader source contains a version directive.
    ThreeShaderNoVersionDirective,
    /// Shader uses pow for a small integer exponent.
    ThreeShaderPreferSmallIntegerPow,
    /// Shader compares a computed distance.
    ThreeShaderPreferSquaredDistanceComparison,
    /// Shader uniform value has an incompatible JavaScript shape.
    ThreeShaderRequireCompatibleUniformValues,
    /// Fragment shader leaves a color output undefined.
    ThreeShaderRequireFragmentOutputOnAllPaths,
    /// Shader stages declare incompatible uniforms.
    ThreeShaderRequireMatchingUniforms,
    /// Shader stage interface does not match.
    ThreeShaderRequireMatchingVaryings,
    /// Vertex shader leaves gl_Position undefined.
    ThreeShaderRequirePositionOnAllPaths,
    /// Shader uniform has no material binding.
    ThreeShaderRequireUniformBindings,
    /// Shader global has an invalid initializer.
    ThreeShaderValidGlobalInitializers,
    /// Shader uniform has an invalid JavaScript definition.
    ThreeShaderValidUniformDefinitions,
    /// Three.js texture repeat without repeat wrapping.
    ThreeTextureRepeatRequiresWrapping,
    /// JavaScript branch reads a TSL uniform value.
    ThreeTslNoJsUniformBranch,
    /// Buffer attribute has a partial final item.
    ThreeValidBufferAttributeArrayLength,
    /// Invalid Three.js buffer attribute item size.
    ThreeValidBufferAttributeItemSize,
    /// Data texture storage is too short.
    ThreeValidDataTextureDataLength,
    /// Data texture has an invalid dimension.
    ThreeValidDataTextureDimensions,
    /// Three.js fog has invalid range parameters.
    ThreeValidFogParameters,
    /// GPU computation has an invalid texture dimension.
    ThreeValidGpuComputationDimensions,
    /// Three.js material opacity outside its normalized range.
    ThreeValidMaterialOpacity,
    /// Invalid Three.js orthographic camera.
    ThreeValidOrthographicCamera,
    /// Three.js PBR material factor outside its normalized range.
    ThreeValidPbrMaterialProperties,
    /// Invalid Three.js perspective camera.
    ThreeValidPerspectiveCamera,
    /// Invalid Three.js physical material property.
    ThreeValidPhysicalMaterialProperties,
    /// Invalid Three.js raycaster distance range.
    ThreeValidRaycasterRange,
    /// Invalid Three.js shadow map size.
    ThreeValidShadowMapSize,
    /// Invalid Three.js spotlight cone.
    ThreeValidSpotLightProperties,
    /// Three.js texture has an incompatible color space.
    ThreeValidTextureColorSpace,
    /// WebGPU high precision conflicts with instanced meshes.
    ThreeWebgpuNoHighPrecisionInstancing,
    /// Legacy EffectComposer used with WebGPURenderer.
    ThreeWebgpuNoLegacyEffectComposer,
    /// Legacy material API used with WebGPURenderer.
    ThreeWebgpuNoLegacyMaterialApi,
    /// WebGPU renderer used before asynchronous initialization.
    ThreeWebgpuRequireInitBeforeSyncOperation,
    /// Synchronous GPU readback inside animation loop.
    WebglNoSyncReadbackInAnimationLoop,
    /// Allocating `new THREE.*` objects inside React Three Fiber `useFrame`.
    R3fNoNewInUseFrame,
    /// Calling a Zustand store hook without a selector (`useStore()`).
    ZustandNoWholeStoreDestructure,
    /// Calling Jotai `selectAtom` inline inside a component render body.
    JotaiSelectAtomInRenderBody,
    /// Calling MobX `reaction` / `autorun` inside `useEffect` without returning its disposer.
    MobxReactionDisposerDiscarded,
    /// Reading a Valtio `useSnapshot` result inside an event handler callback instead of the proxy.
    ValtioNoSnapshotInCallback,
    /// Importing from `'react'` in a pure Preact project.
    PreactNoReactImport,
    /// Raw text outside Ink `<Text>` in terminal UI components.
    InkNoRawText,
    /// Deprecated Zod v4 `.strict()` / `.passthrough()` / `.strip()` schema calls.
    ZodV4DeprecatedParse,
    /// Ambiguous link text.
    AnchorAmbiguousText,
    /// Anchor has no content.
    AnchorHasContent,
    /// Anchor used as a button.
    AnchorIsValid,
    /// Fragment link target is missing.
    AnchorTargetExists,
    /// aria-activedescendant missing tabindex.
    AriaActivedescendantHasTabindex,
    /// Braille-only accessible description.
    AriaBrailleEquivalent,
    /// Invalid ARIA attribute.
    AriaProps,
    /// Invalid ARIA attribute value.
    AriaProptypes,
    /// Invalid ARIA role.
    AriaRole,
    /// ARIA on unsupported element.
    AriaUnsupportedElements,
    /// Invalid autocomplete value.
    AutocompleteValid,
    /// Base UI dialog popup without a title.
    BaseUiDialogPopupRequiresTitle,
    /// Base UI field control without a label.
    BaseUiFieldRequiresLabel,
    /// Click handler missing keyboard handler.
    ClickEventsHaveKeyEvents,
    /// Control missing accessible label.
    ControlHasAssociatedLabel,
    /// Data table has no accessible name.
    DataTableRequiresAccessibleName,
    /// Em dash in JSX text.
    DesignNoEmDashInJsxText,
    /// Redundant padding axes.
    DesignNoRedundantPaddingAxes,
    /// Redundant width and height axes.
    DesignNoRedundantSizeAxes,
    /// space-* utility on flex children.
    DesignNoSpaceOnFlexChildren,
    /// Three dots instead of ellipsis.
    DesignNoThreePeriodEllipsis,
    /// Details disclosure has no explicit summary.
    DetailsRequiresSummary,
    /// Dialog without accessible name.
    DialogHasAccessibleName,
    /// Table header has no accessible text.
    EmptyTableHeader,
    /// Fieldset group has no legend.
    FieldsetRequiresLegend,
    /// Form control is omitted from named submission data.
    FormControlRequiresName,
    /// Heading has no content.
    HeadingHasContent,
    /// html element missing lang.
    HtmlHasLang,
    /// Interactive control contains another focusable control.
    HtmlNoNestedInteractive,
    /// Conflicting document language declarations.
    HtmlXmlLangMismatch,
    /// iframe missing title.
    IframeHasTitle,
    /// Frame title is duplicated.
    IframeTitleUnique,
    /// Redundant words in image alt.
    ImgRedundantAlt,
    /// Invalid Ink accessibility semantics.
    InkValidAriaSemantics,
    /// Interactive element not focusable.
    InteractiveSupportsFocus,
    /// Label missing associated control.
    LabelHasAssociatedControl,
    /// Invalid lang attribute value.
    Lang,
    /// Loading state removes its initiating action.
    LoadingActionPreservesTrigger,
    /// Media missing captions.
    MediaHasCaption,
    /// Mouse handler missing focus handler.
    MouseEventsHaveKeyEvents,
    /// accessKey attribute used.
    NoAccessKey,
    /// Long body copy is set in all caps.
    NoAllCapsBodyText,
    /// Pixel arbitrary font size.
    NoArbitraryPxFontSize,
    /// Document body hidden from assistive technology.
    NoAriaHiddenOnBody,
    /// aria-hidden on focusable element.
    NoAriaHiddenOnFocusable,
    /// Invalid control has no error description.
    NoAriaInvalidWithoutDescription,
    /// Status live region interrupts assistive technology.
    NoAssertiveStatus,
    /// Content auto-scrolls forever.
    NoAutoScrollingContent,
    /// Autofocus on an element.
    NoAutofocus,
    /// Autoplaying media without muted.
    NoAutoplayWithoutMuted,
    /// Paste blocked in an authentication field.
    NoBlockedPaste,
    /// Image has no usable source.
    NoBrokenImageSource,
    /// Overlay can be clipped by an overflow container.
    NoClippedOverlay,
    /// Page root uses a generic default font choice.
    NoCommonRootFont,
    /// Controlled selection change steals focus.
    NoControlledSelectionFocusEffect,
    /// Bounded text container has cramped padding.
    NoCrampedContainerPadding,
    /// Letter spacing compresses text excessively.
    NoCrushedLetterSpacing,
    /// Colored glow on dark background.
    NoDarkModeGlow,
    /// Empty blurred color orb decorates the layout.
    NoDecorativeBlurOrb,
    /// Surface draws a decorative grid background.
    NoDecorativeGridBackground,
    /// Stable copy pulses for attention.
    NoDecorativePulse,
    /// Large decorative radial spotlight.
    NoDecorativeRadialSpotlight,
    /// Page root uses a default purple-spectrum gradient.
    NoDefaultPurplePageGradient,
    /// Page defaults to a warm off-white surface.
    NoDefaultWarmPageSurface,
    /// Deprecated Tailwind v4 utility.
    NoDeprecatedTailwindClass,
    /// Zoom disabled on viewport.
    NoDisabledZoom,
    /// Distracting marquee or blink element.
    NoDistractingElements,
    /// Referenced ID is duplicated.
    NoDuplicateStaticIdReference,
    /// Tailwind utility is assembled dynamically.
    NoDynamicTailwindClassFragment,
    /// UI motion starts with ease-in.
    NoEaseInMotion,
    /// Heading uses emoji as decoration.
    NoEmojiHeadingDecoration,
    /// Empty semantic element renders as a card.
    NoEmptyCardShell,
    /// Page boxes too many groups into cards.
    NoExcessiveCardSurfaces,
    /// Page centers multiple body-copy blocks.
    NoExcessiveCenteredCopy,
    /// Page mixes too many font families.
    NoExcessiveFontFamilies,
    /// Motion child stagger is too long.
    NoExcessiveMotionStagger,
    /// Page overuses pill-shaped treatments.
    NoExcessivePillTreatment,
    /// Preview redraws decorative browser chrome.
    NoFakeBrowserChrome,
    /// Fixed element is scoped by a transformed ancestor.
    NoFixedInsideTransformedAncestor,
    /// Page typography uses a compressed size range.
    NoFlatPageTypeScale,
    /// Focus waits for animation completion.
    NoFocusInAnimationCompletionHandler,
    /// aria-hidden subtree contains focusable content.
    NoFocusableContentInAriaHidden,
    /// Focusable control inside role=text.
    NoFocusableContentInRoleText,
    /// Hero uses a full-viewport centered template.
    NoFullViewportCenteredHero,
    /// Full viewport width causes overflow.
    NoFullViewportWidth,
    /// Page uses generic marketing language.
    NoGenericMarketingCopy,
    /// Compact icon tile uses a generic purple-to-blue gradient.
    NoGenericPurpleBlueIconGradient,
    /// Gradient text is hard to read.
    NoGradientText,
    /// Gray text on colored background.
    NoGrayOnColoredBackground,
    /// Hairline border is paired with a diffuse shadow.
    NoHairlineBorderWideShadow,
    /// Hero uses a decorative eyebrow label.
    NoHeroEyebrowChip,
    /// Content is revealed only on hover.
    NoHoverOnlyReveal,
    /// Card stacks an icon tile above its heading.
    NoIconTileHeadingStack,
    /// Image scales or rotates on hover.
    NoImageHoverTransform,
    /// Image has no reserved layout space.
    NoImgWithoutDimensions,
    /// Pointer cursor has no interaction.
    NoInertPointerAffordance,
    /// Sticky positioning has no inset.
    NoInertStickyPosition,
    /// Bouncy easing animation.
    NoInlineBounceEasing,
    /// Large inline style object rebuilds every render.
    NoInlineExhaustiveStyle,
    /// Interactive element given noninteractive role.
    NoInteractiveElementToNoninteractiveRole,
    /// Progress value falls outside its range.
    NoInvalidProgressRange,
    /// Invisible native control lacks keyboard focus treatment.
    NoInvisibleFocusControl,
    /// Display heading combines italic serif styling.
    NoItalicSerifDisplayHeading,
    /// Justified text without hyphens.
    NoJustifiedText,
    /// Interaction state changes layout geometry.
    NoLayoutShiftingInteractionState,
    /// Animating layout properties.
    NoLayoutTransitionInline,
    /// Transition duration too long.
    NoLongTransitionDuration,
    /// Low-contrast text in inline style.
    NoLowContrastInlineStyle,
    /// Page repeatedly uses manufactured contrast copy.
    NoManufacturedContrastCopy,
    /// CSS and Motion animate the same property.
    NoMixedAnimationOwners,
    /// File mixes visual icon families.
    NoMixedIconLibraries,
    /// Page repeats one spacing value throughout.
    NoMonotonousPageSpacing,
    /// View contains multiple main landmarks.
    NoMultipleMainLandmarks,
    /// Repeated navigation landmarks need unique names.
    NoMultipleUnlabeledNavigationLandmarks,
    /// Card surface is nested inside another card.
    NoNestedCardSurface,
    /// Handler on non-interactive element.
    NoNoninteractiveElementInteractions,
    /// Noninteractive element given interactive role.
    NoNoninteractiveElementToInteractiveRole,
    /// Tabindex on non-interactive element.
    NoNoninteractiveTabindex,
    /// Textarea resizing is disabled.
    NoNonresizableTextarea,
    /// Styled numbers are used as section decoration.
    NoNumberedSectionMarkers,
    /// outline:none removes focus ring.
    NoOutlineNone,
    /// Hover state stacks too many effects.
    NoOverloadedHoverState,
    /// Long headline uses an oversized display scale.
    NoOversizedLongHeading,
    /// Text measure is too wide.
    NoOverwideTextMeasure,
    /// Navigation count uses a pill badge.
    NoPillNavigationCount,
    /// Field relies on placeholder text for its label.
    NoPlaceholderOnlyField,
    /// Page renders a placeholder persona.
    NoPlaceholderPersonaCopy,
    /// Enabled control ignores pointer input.
    NoPointerDisabledEnabledControl,
    /// Presentational element exposes conflicting semantics.
    NoPresentationRoleConflict,
    /// Decorative status dot pulses continuously.
    NoPulsingStatusDot,
    /// Pure black background.
    NoPureBlackBackground,
    /// Surface uses a pure-black shadow.
    NoPureBlackShadow,
    /// Saturated radial halo on a dark surface.
    NoRadialHalo,
    /// Reduced motion removes meaningful content.
    NoReducedMotionContentRemoval,
    /// Redundant display utility.
    NoRedundantDisplayClass,
    /// Redundant ARIA role.
    NoRedundantRoles,
    /// Title tooltip repeats visible control text.
    NoRedundantTitleTooltip,
    /// A card repeats the same text in distinct slots.
    NoRepeatedContainerText,
    /// Page repeats boxed emoji as feature icons.
    NoRepeatedEmojiTiles,
    /// Page repeats glass panels.
    NoRepeatedGlassSurfaces,
    /// Hover scaling repeats across the page.
    NoRepeatedHoverScale,
    /// Repeated tracked labels scaffold multiple sections.
    NoRepeatedKickerLabels,
    /// Navigation repeats placeholder destinations.
    NoRepeatedPlaceholderNavigation,
    /// Page repeats the same padded section shell.
    NoRepeatedSectionShells,
    /// Surface uses a repeating gradient texture.
    NoRepeatingGradientDecoration,
    /// Responsive styles hide a control's accessible name.
    NoResponsiveHiddenAccessibleName,
    /// Server-side image map.
    NoServerSideImageMap,
    /// Large illustration is assembled from primitive shapes.
    NoShapeAssembledIllustration,
    /// Thick one-sided stripe.
    NoSideTabBorder,
    /// Heading hierarchy skips a level.
    NoSkippedHeadingLevel,
    /// Form control text is smaller than 16px.
    NoSmallFormControlText,
    /// Smooth scrolling ignores reduced motion.
    NoSmoothScrollWithoutReducedMotion,
    /// Interaction on static element.
    NoStaticElementInteractions,
    /// MotionConfig always ignores reduced motion.
    NoStaticMotionConfigNever,
    /// currentColor fights a fill/stroke class.
    NoSvgCurrentcolorWithFillClass,
    /// Text button uses symmetric padding.
    NoSymmetricTextButtonPadding,
    /// Animating a layout property.
    NoTailwindLayoutTransition,
    /// Long all-caps heading has collision-prone leading.
    NoTightAllCapsHeading,
    /// Body copy has cramped line spacing.
    NoTightBodyLeading,
    /// Display heading uses the tightest tracking preset.
    NoTightDisplayTracking,
    /// Text is too small.
    NoTinyText,
    /// Tiny label combines uppercase text and decorative tracking.
    NoTinyUppercaseTrackedLabel,
    /// Composite widget state feedback is delayed.
    NoTransitionedCompositeWidgetState,
    /// Focus indicator animates into view.
    NoTransitionedFocusRing,
    /// Icon button target is smaller than 24px.
    NoUndersizedIconButton,
    /// Tailwind animation ignores reduced motion.
    NoUngatedTailwindAnimation,
    /// Feature grid repeats one card recipe.
    NoUniformFeatureCardGrid,
    /// Uninformative aria-label.
    NoUninformativeAriaLabel,
    /// Short label uses uppercase monospace styling.
    NoUppercaseMonoLabel,
    /// Navigation label uses uppercase tracking.
    NoUppercaseTrackedNavigationLabel,
    /// Wide letter spacing on body text.
    NoWideLetterSpacing,
    /// Excessively high z-index.
    NoZIndex9999,
    /// Use dvh instead of vh for full height.
    PreferDvhOverVh,
    /// Custom modal instead of dialog.
    PreferHtmlDialog,
    /// Motion individual transforms miss compositor acceleration.
    PreferMotionTransformProperty,
    /// Changing table numbers use proportional figures.
    PreferTabularNumericData,
    /// Role used instead of HTML tag.
    PreferTagOverRole,
    /// Use truncate shorthand.
    PreferTruncateShorthand,
    /// Radio input missing name.
    RadioInputMissingName,
    /// Radix dialog content without a title.
    RadixDialogContentRequiresTitle,
    /// React Aria dialog without a heading.
    ReactAriaDialogRequiresHeading,
    /// Autoplay video has no poster frame.
    RequireAutoplayVideoPoster,
    /// Scaled menu omits its transform origin.
    RequireScaleRevealTransformOrigin,
    /// ARIA button handles only one activation key.
    RoleButtonRequiresCompleteKeyboardActivation,
    /// Role missing required ARIA props.
    RoleHasRequiredAriaProps,
    /// Unsupported ARIA prop for role.
    RoleSupportsAriaProps,
    /// scope attribute on non-th element.
    Scope,
    /// Dialog content without a title.
    ShadcnDialogContentRequiresTitle,
    /// FormItem control without a label.
    ShadcnFormItemRequiresLabel,
    /// Icon-only Button without accessible name.
    ShadcnIconButtonRequiresLabel,
    /// Duplicate CSS property in styled block.
    StyledComponentsDuplicateCssPropertyInBlock,
    /// Positive tabindex value.
    TabindexNoPositive,
    // --- Ticket 08 rules ---
    /// Defaulted empty `{}` or `[]` prop breaks `React.memo` or hook dependency stability.
    RerenderMemoWithDefaultValue,
    /// `useMemo` building JSX before an early return that ignores it.
    RerenderMemoBeforeEarlyReturn,
    /// Continuous hook value (`useWindowWidth`, `useScrollPosition`) used only for a threshold boolean.
    RerenderDerivedStateFromHook,
    /// Calling `setState` on every high-frequency DOM event (`scroll`, `mousemove`, `wheel`) without transition/throttle.
    RerenderTransitionsScroll,
    /// Calling `matchMedia()` inside a `useState` initializer.
    NoMatchMediaInStateInitializer,
    /// Using `transition: all` or `transition-all` which animates layout properties.
    NoTransitionAll,
    /// Animating layout-triggering CSS properties (`width`, `height`, `top`, `left`, `margin`, `padding`).
    NoLayoutPropertyAnimation,
    /// Passing an inline object, array, function, or JSX prop to a `memo()`-wrapped component.
    NoInlinePropOnMemoComponent,
    /// `await` before an early-return guard that does not depend on the awaited value.
    AsyncDeferAwait,
    /// Passing a local unmemoized object/array/function binding as `Context.Provider` `value`.
    ContextProviderValueFromUnmemoizedLocalLiteral,
    /// Wrapping a trivially cheap expression in `useMemo`.
    NoUsememoSimpleExpression,
    /// Using an inline `[]` or `{}` as a `||` / `??` fallback prop on a memoized component.
    PreferStableEmptyFallback,
    /// Constructing a non-trivial `new X()` eagerly inside `useState(new X())`.
    NoEagerNewInUseStateInitializer,
    /// Keeping `will-change` permanently active in JSX `className` or `style`.
    NoPermanentWillChange,
    /// Recursive `requestAnimationFrame` callback with no stop condition and discarded request ID.
    NoUnboundedAnimationFrameLoop,
    /// Unthrottled DOM style or animation mutation inside a `scroll` listener.
    NoUnthrottledScrollMutation,
    /// Responsive `<img srcSet="...">` with width descriptors missing `sizes`.
    NoSrcsetWithoutSizes,
    /// `<img loading="lazy" fetchPriority="high">` with contradictory loading hints.
    NoImgLazyWithHighFetchpriority,
    /// Static JSX element assigned to a `const` inside a component body instead of module scope.
    RenderingHoistJsx,
    /// `<script src="...">` without `defer` or `async`.
    RenderingScriptDeferAsync,
    /// Nondeterministic time or random call (`new Date()`, `Date.now()`, `Math.random()`) rendered in JSX.
    RenderingHydrationMismatchTime,
    /// Mount-only `useEffect` state synchronization causing post-paint hydration flash.
    RenderingHydrationNoFlicker,
    /// Rendering different JSX branches on server vs. client by branching on browser globals.
    NoHydrationBranchOnBrowserGlobal,
    /// Reading unguarded browser globals (`window`, `document`, `localStorage`, `navigator`) during render or hook init.
    NoUnguardedBrowserGlobalInRenderOrHookInit,
    /// Locale- or timezone-dependent formatting during SSR render without explicit locale/timeZone.
    NoLocaleFormatInRender,
    /// Calling `motionValue()` directly during React render instead of `useMotionValue()`.
    MotionValueConstructorInRender,
    /// Mixing spring physics options (`stiffness`/`damping`/`mass`) with `duration`/`bounce`.
    NoConflictingSpringOptions,
    /// Mutating a CSS custom property on `document.documentElement` or `document.body` inside an animation loop.
    NoGlobalCssVariableAnimation,
    /// Animating a `blur(...)` filter exceeding 10px radius.
    NoLargeAnimatedBlur,
    /// Using `React.lazy` on a React Router route `Component`/`element` instead of route `lazy`.
    ReactRouterPreferRouteLazy,
    /// Sequential independent `fetch` awaits inside a React Router `loader`/`clientLoader`.
    ReactRouterLoaderParallelFetch,
    /// `fetch()` inside a React Router `loader`/`clientLoader` that does not forward `request.signal`.
    ReactRouterLoaderFetchForwardsSignal,
    /// Retired rule: `no-scale-from-zero`.
    NoScaleFromZero,
    /// Retired rule: `rendering-animate-svg-wrapper`.
    RenderingAnimateSvgWrapper,
    /// Retired rule: `rendering-usetransition-loading`.
    RenderingUsetransitionLoading,
    /// Sequential independent `await` statements that can run concurrently via `Promise.all()`.
    AsyncParallel,
    /// Spreading the accumulator inside `.reduce()` / `.reduceRight()` causing $O(n^2)$ copying.
    NoSpreadAccumulatorInReduce,
    /// Deep-cloning with `JSON.parse(JSON.stringify(x))` instead of `structuredClone(x)`.
    NoJsonParseStringifyClone,
    /// Synchronous `XMLHttpRequest.open(method, url, false)` blocking the main thread.
    NoSyncXhr,
    /// Calling `document.write()` or `document.writeln()`.
    NoDocumentWrite,
    /// Calling `URL.createObjectURL()` without a matching `URL.revokeObjectURL()`.
    NoCreateObjectUrlWithoutRevoke,
    /// Chained `.map()` / `.filter()` array iterations that traverse the list multiple times.
    JsCombineIterations,
    /// Repeated `Array.includes()` / `Array.indexOf()` lookups inside a loop instead of `Set`/`Map`.
    JsSetMapLookups,
    /// Constructing `new RegExp()` with a static pattern inside a loop.
    JsHoistRegexp,
    /// Constructing `new Intl.*()` inside a function or render body without caching/memoization.
    JsHoistIntl,
    /// Chained `.map().filter(Boolean)` traversing the array twice.
    JsFlatmapFilter,
    /// Sorting an array with `.sort()` only to read its minimum or maximum element.
    JsMinMaxLoop,
    /// Comparing two arrays with `.every()` without checking `.length` equality first.
    JsLengthCheckFirst,
    /// Calling `array.find()` / `array.findIndex()` with an equality predicate inside a loop.
    JsIndexMaps,
    /// Reading the same `localStorage` / `sessionStorage` key multiple times in one function.
    JsCacheStorage,
    /// Reading the same deep property chain (`a.b.c`) 3+ times inside a loop.
    JsCachePropertyAccess,
    /// Interleaving multiple DOM `.style` writes with layout reads inside a loop.
    JsBatchDomCss,
    /// Async `.reduce()` callback that does not `await` its accumulator parameter.
    JsAsyncReduceWithoutAwaitedAcc,
    /// Retired rule: `js-tosorted-immutable`.
    JsTosortedImmutable,
    /// Retired rule: `js-early-exit`.
    JsEarlyExit,
    /// Registering `wheel`, `mousewheel`, `touchstart`, or `touchmove` listener without `{ passive: true }`.
    ClientPassiveEventListeners,
    /// Retired rule: `client-localstorage-no-version`.
    ClientLocalstorageNoVersion,
    /// Importing and calling `flushSync` from `react-dom`, skipping View Transitions and concurrent rendering.
    NoFlushSync,
    /// Calling `document.startViewTransition()` directly in a file that imports React's `<ViewTransition>`.
    NoDocumentStartViewTransition,
    /// Importing from a barrel (`index.ts`) file instead of the direct source module.
    NoBarrelImport,
    /// Importing from the full `'lodash'` bundle instead of `'lodash/<fn>'` subpaths.
    NoFullLodashImport,
    /// Importing `'moment'` instead of lightweight alternatives (`date-fns`, `dayjs`).
    NoMoment,
    /// Eagerly importing a heavy library (`monaco-editor`, `recharts`, `chart.js`, `mermaid`, etc.).
    PreferDynamicImport,
    /// Non-static dynamic `import(expr)` or `require(expr)` that prevents bundler code-splitting.
    NoDynamicImportPath,
    /// External third-party `<script src="https://...">` without `defer` or `async`.
    NoUndeferredThirdParty,
    /// Importing full `motion` from `framer-motion` / `motion/react` instead of `LazyMotion` + `m`.
    UseLazyMotion,
    /// Using both `children` and `dangerouslySetInnerHTML` on the same JSX element.
    NoDangerWithChildren,
    /// `<iframe>` element missing `sandbox` attribute.
    IframeMissingSandbox,
    /// `javascript:` URL in JSX attribute.
    JsxNoScriptUrl,
    /// `target="_blank"` link without `rel="noreferrer"` or `rel="noopener"`.
    JsxNoTargetBlank,
    /// `window.open` call without `'noopener'` in features.
    WindowOpenWithoutNoopener,
    /// Hardcoded secret or client-exposed secret variable in browser code.
    NoSecretsInClientCode,
    /// Persisting an authentication token in `localStorage` or `sessionStorage`.
    AuthTokenInWebStorage,
    /// Dynamic code execution via `eval()`, `new Function()`, or string `setTimeout`/`setInterval`.
    NoEval,
    /// Path containment check using `.startsWith(root)` without a trailing path separator.
    NoPathPrefixContainment,
    /// `<ReactMarkdown>` with `rehype-raw` and no `rehype-sanitize` or sanitizer on dynamic content.
    ReactMarkdownUnsanitizedRawHtml,
    /// Mismatched CSP `nonce` between `<ServerRouter>` and React server stream options.
    ReactRouterCspNonceConsistency,
    /// Executable SVG asset or `dangerouslyAllowSVG: true` exposure.
    ActiveStaticAsset,
    /// Agent tool definition exposing shell, filesystem, network, or code-execution primitives.
    AgentToolCapabilityRisk,
    /// Browser artifact shipping Firebase/Supabase config together with sensitive collection/authz fields.
    ArtifactBaasAuthoritySurface,
    /// Server secret environment variable names or full env dump leaked into a browser artifact.
    ArtifactEnvLeak,
    /// Secret credential value shipped inside a browser artifact.
    ArtifactSecretLeak,
    /// CI/build pipeline running lifecycle scripts without `--ignore-scripts` near secrets.
    BuildPipelineSecretBoundary,
    /// Unvalidated redirect target or permissive framing (`frame-ancestors *` / `X-Frame-Options: ALLOW`).
    ClickjackingRedirectRisk,
    /// Shell or process command execution interpolated with caller-controlled request input.
    CommandExecutionInputRisk,
    /// Credentialed CORS with wildcard/docs origin or broad parent-domain auth cookie.
    CorsCookieTrustRisk,
    /// Dynamic HTML sink (`dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`) with unsanitized input.
    DangerousHtmlSink,
    /// Client Firebase/Firestore write setting an ownership, tenant, or role authorization field.
    FirebaseClientOwnedAuthzField,
    /// Permissive Firebase security rule (`allow read, write: if true` or `request.auth != null`).
    FirebasePermissiveRules,
    /// Firestore `.where(...)` client filter relied on as an authorization boundary.
    FirebaseQueryFilterAsAuth,
    /// GitHub/GitLab/Bitbucket API URL built with unencoded caller-controlled interpolation.
    GitProviderUrlInjectionRisk,
    /// Imported metadata, EXIF, manifest, or archive input reaching code/command execution.
    ImportMetadataExecutionRisk,
    /// Weak cryptographic hash/cipher (`md5`, `sha1`, `DES`, `RC4`), `Math.random()` for secrets, or timing-unsafe signature comparison.
    InsecureCryptoRisk,
    /// Auth/session cookie set without `HttpOnly` (`httpOnly: false` or `document.cookie`).
    InsecureSessionCookie,
    /// JWT verification configured with the `'none'` algorithm.
    JwtInsecureVerification,
    /// Private key PEM block or long-lived signing/deploy key material committed in repository.
    KeyLifecycleRisk,
    /// Localhost RPC or WebSocket native bridge exposing update/install/exec capabilities without strict origin checks.
    LocalRpcNativeBridgeRisk,
    /// MCP server tool handler exposing raw shell, filesystem, network, or code-execution capability.
    McpToolCapabilityRisk,
    /// Server-side MDX compilation (`compileMDX`, `MDXRemote`, `evaluateMdx`) over untrusted content or with `rehypeRaw`.
    MdxSsrExecutionRisk,
    /// NoSQL query accepting `$where`, `$regex`, or unvalidated `JSON.parse(req.*)` operator input.
    NosqlInjectionRisk,
    /// `package.json` metadata containing secret values, JWTs, or suspicious public env secret names.
    PackageMetadataSecret,
    /// Filesystem read/write or `path.join`/`path.resolve` using unvalidated request/query/params input.
    PathTraversalRisk,
    /// Remote script execution (`curl ... | sh`) or unsigned updater/plugin archive download without checksum verification.
    PluginUpdateTrustRisk,
    /// `window.addEventListener('message', ...)` or `window.onmessage` reading `event.data` without checking `event.origin`.
    PostmessageOriginRisk,
    /// Browser-reachable debug log, env dump, sql dump, or sourceless trace artifact under `public/`.
    PublicDebugArtifact,
    /// Public client env variable (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`) named like a secret or private key.
    PublicEnvSecretName,
    /// Raw SQL query built via string concatenation/interpolation or unsafe raw query helper (`$queryRawUnsafe`).
    RawSqlInjectionRisk,
    /// Committed `.env`, service-account JSON, `.npmrc`, or credential file containing live secrets.
    RepositorySecretFile,
    /// Spreading or `Object.assign`/`_.merge`-ing raw `req.body`/`req.query` without a field allowlist.
    RequestBodyMassAssignment,
    /// Secret environment variable read with a hardcoded string literal fallback (`process.env.SECRET ?? "fallback"`).
    SecretInFallback,
    /// Client Supabase `.insert`/`.update`/`.upsert` writing owner, tenant, or role authorization columns.
    SupabaseClientOwnedAuthzField,
    /// Supabase SQL migration disabling RLS, granting `using (true)` write policies, or checking `auth.role() = 'service_role'`.
    SupabaseRlsPolicyRisk,
    /// Supabase `create table` in `public` schema without `alter table ... enable row level security`.
    SupabaseTableMissingRls,
    /// `<iframe>` rendered through an SVG/CSS `filter: url(#...)` clickjacking primitive.
    SvgFilterClickjackingRisk,
    /// TanStack Start `createServerFn({ method: 'GET' })` performing a state mutation.
    TanstackStartGetMutation,
    /// TanStack Start route `loader` accessing server-only secrets outside `createServerFn`.
    TanstackStartNoSecretsInLoader,
    /// Server route composing tenant/subdomain/workspace input directly into a static/CDN/S3 asset fetch path.
    TenantStaticProxyRisk,
    /// Unescaped `JSON.stringify(...)` injected into `dangerouslySetInnerHTML` or inline `<script>` markup.
    UnsafeJsonInHtml,
    /// Server-side `fetch`/`axios`/`got` to a caller-controlled URL without `redirect: "manual"`.
    UntrustedRedirectFollowing,
    /// Client code reading privileged action parameters (`role`, `admin`, `invite`, `redirect_uri`, `callbackUrl`) directly from URL searchParams.
    UrlPrefilledPrivilegedAction,
    /// Webhook POST handler reading request payload without verifying the provider's cryptographic signature.
    WebhookSignatureRisk,
    /// Blocking `console.*` or analytics/telemetry call in a Server Action or Route Handler not deferred with `after()`.
    ServerAfterNonblocking,
    /// Calling a `React.cache(fn)` function with a fresh inline object or array literal argument.
    ServerCacheWithObjectLiteral,
    /// Passing both a source array and a derived array (`.filter`, `.map`, `.slice`, `.toSorted`) as props from a Server Component.
    ServerDedupProps,
    /// `fetch(url)` in a Next.js App Router server file without `cache` or `next: { revalidate }` / `next: { tags }`.
    ServerFetchWithoutRevalidate,
    /// Static `fs.readFile*` or `fetch(new URL(..., import.meta.url))` inside a route handler instead of hoisted to module scope.
    ServerHoistStaticIo,
    /// Mutable module-scope `let`/`var` or mutated `const` collection in a `"use server"` module shared across requests.
    ServerNoMutableModuleState,
    /// Sequential `await` declarations of independent async operations that do not share cached work.
    ServerSequentialIndependentAwait,
    /// `async` component function declared in a `"use client"` module.
    NextjsAsyncClientComponent,
    /// Synchronous property access, destructuring, spread, or iteration on Next.js 15+ async `cookies()`, `headers()`, `draftMode()`, `params`, or `searchParams`.
    NextjsAsyncDynamicApiNotAwaited,
    /// Next.js App Router `error.tsx` or `global-error.tsx` missing the `'use client'` directive.
    NextjsErrorBoundaryMissingUseClient,
    /// Next.js App Router `global-error.tsx` missing root `<html>` and `<body>` elements.
    NextjsGlobalErrorMissingHtmlBody,
    /// `<Image fill />` from `next/image` without a `sizes` attribute.
    NextjsImageMissingSizes,
    /// Inline `<Script>` from `next/script` without an `id` attribute.
    NextjsInlineScriptMissingId,
    /// Disagreement between `alternates.canonical` and `openGraph.url` in exported Next.js `metadata`.
    NextjsMetadataUrlConsistency,
    /// Public Next.js App Router `page.tsx` without `metadata` or `generateMetadata` export and no ancestor layout metadata.
    NextjsMissingMetadata,
    /// Plain `<a href="/...">` for internal navigation in Next.js instead of `<Link>` from `next/link`.
    NextjsNoAElement,
    /// `useEffect` + `fetch()` inside a `"use client"` Next.js page or layout instead of fetching in a Server Component.
    NextjsNoClientFetchForServerData,
    /// Client-side redirect (`router.push` / `router.replace` / `window.location`) inside `useEffect` on mount.
    NextjsNoClientSideRedirect,
    /// `<link rel="stylesheet">` for local stylesheets bypassing Next.js CSS bundling.
    NextjsNoCssLink,
    /// `export default` in a Next.js App Router `route.ts` file without named HTTP method exports.
    NextjsNoDefaultExportInRouteHandler,
    /// `export const runtime = 'edge'` inside an `opengraph-image` or `twitter-image` route.
    NextjsNoEdgeOgRuntime,
    /// Loading Google Fonts via `<link href="https://fonts.googleapis.com/...">` instead of `next/font/google`.
    NextjsNoFontLink,
    /// Manual Google Analytics `<script>` / `<Script>` tag instead of `@next/third-parties/google`.
    NextjsNoGoogleAnalyticsScript,
    /// Importing `next/head` inside the Next.js App Router (`app/` directory).
    NextjsNoHeadImport,
    /// Native `<script src="...">` tag in Next.js instead of `<Script>` from `next/script`.
    NextjsNoNativeScript,
    /// Loading redundant polyfill CDN scripts (`polyfill.io`) already bundled by Next.js.
    NextjsNoPolyfillScript,
    /// Calling `redirect()`, `permanentRedirect()`, `notFound()`, `forbidden()`, or `unauthorized()` inside a `try` block without `unstable_rethrow`.
    NextjsNoRedirectInTryCatch,
    /// Rendering `next/script` `<Script>` inside `next/head` `<Head>`.
    NextjsNoScriptInHead,
    /// Performing state mutations, cookie writes, or mutating fetches inside a Next.js `GET` route handler.
    NextjsNoSideEffectInGetHandler,
    /// Calling `useSearchParams()` in a Next.js page/layout without an enclosing `<Suspense>` boundary.
    NextjsNoUseSearchParamsWithoutSuspense,
    /// Importing `@vercel/og` directly instead of `next/og`.
    NextjsNoVercelOgImport,
    /// Missing or weakened pnpm supply-chain hardening settings (`minimumReleaseAge`, `blockExoticSubdeps`, `trustPolicy`) in `pnpm-workspace.yaml`.
    RequirePnpmHardening,
    /// Installed `react-server-dom-*` or `next` version affected by React Server Components RCE (CVE-2025-55182) or DoS (CVE-2026-23870) advisories.
    NoVulnerableReactServerComponents,
    /// Direct dependency scoring below the minimum threshold on Socket.dev's supply-chain or vulnerability security axes.
    LowSupplyChainScore,
    /// Spreading a whole TanStack Query result subscribes to every field.
    QueryDestructureResult,
    /// Unhandled floating `mutateAsync()` promise from TanStack `useMutation`.
    QueryFloatingMutateAsync,
    /// TanStack `useMutation` missing cache invalidation or update in lifecycle callbacks.
    QueryMutationMissingInvalidation,
    /// Invoking a read-style TanStack `useMutation` inside `useEffect` instead of `useQuery`.
    QueryNoMutationInEffectAsRead,
    /// Calling TanStack Query `refetch()` unconditionally inside `useEffect`.
    QueryNoQueryInEffect,
    /// Rest-destructuring a TanStack Query result (`const { data, ...rest } = useQuery(...)`).
    QueryNoRestDestructuring,
    /// Using TanStack `useQuery` for an HTTP mutation (`POST`/`PUT`/`PATCH`/`DELETE`).
    QueryNoUseQueryForMutation,
    /// Constructing `new QueryClient()` inside a component render body.
    QueryStableQueryClient,
    /// Independent sequential `await` expressions inside a TanStack Start route `loader`.
    TanstackStartLoaderParallelFetch,
    /// Root route `<head>` missing `<HeadContent />` in TanStack Start.
    TanstackStartMissingHeadContent,
    /// Root route `<body>` missing `<Scripts />` in TanStack Start.
    TanstackStartMissingScripts,
    /// Plain `<a href="/...">` internal link in TanStack Start routes instead of `<Link>`.
    TanstackStartNoAnchorElement,
    /// Retired rule: direct `fetch` inside a TanStack Start route loader.
    TanstackStartNoDirectFetchInLoader,
    /// Dynamic `import("*.functions")` of a TanStack Start server functions module.
    TanstackStartNoDynamicServerFnImport,
    /// Calling `navigate()` synchronously during render in TanStack Start.
    TanstackStartNoNavigateInRender,
    /// Calling `fetch()` inside `useEffect` in a TanStack Start route instead of `loader`.
    TanstackStartNoUseEffectFetch,
    /// Redundant `"use server"` directive inside a TanStack Start `createServerFn` `.handler(...)`.
    TanstackStartNoUseServerInHandler,
    /// `throw redirect()` or `throw notFound()` caught by an enclosing `try`/`catch` without re-throwing.
    TanstackStartRedirectInTryCatch,
    /// Out-of-order route options properties in `createFileRoute` / `createRoute` breaking type inference.
    TanstackStartRoutePropertyOrder,
    /// Out-of-order `createServerFn` chained methods breaking type inference.
    TanstackStartServerFnMethodOrder,
    /// Retired rule: animating layout properties in React Native.
    RnAnimateLayoutProperty,
    /// Using `useAnimatedReaction` solely to copy one shared value into another instead of `useDerivedValue`.
    RnAnimationReactionAsDerived,
    /// Passing ignored scroll props (`scrollEventThrottle`, `decelerationRate`, `onScrollBeginDrag`) to `BottomSheetScrollView`.
    RnBottomSheetNoIgnoredScrollProp,
    /// Updating React state inside `@gorhom/bottom-sheet` `onAnimate`.
    RnBottomSheetNoStateInOnAnimate,
    /// Importing a JS-driven bottom sheet library instead of native `formSheet` modal presentation.
    RnBottomSheetPreferNative,
    /// Nesting React Native scrollables inside `@gorhom/bottom-sheet` instead of integrated `BottomSheet*` scrollables.
    RnBottomSheetUseIntegratedScrollable,
    /// Un-awaited Detox element action, `waitFor`, or `expect` call in E2E tests.
    RnDetoxMissingAwait,
    /// Creating an inline press handler closure per row inside list `renderItem`.
    RnListCallbackPerRow,
    /// Passing a freshly allocated `.map()` / `.filter()` / `[...]` array to list `data`.
    RnListDataMapped,
    /// `FlashList` or `LegendList` missing `estimatedItemSize`.
    RnListMissingEstimatedItemSize,
    /// Heterogeneous root item shapes in `FlashList` / `LegendList` `renderItem` without `getItemType`.
    RnListRecyclableWithoutTypes,
    /// Deep subpath import from `react-native/Libraries/*` for a root-exported symbol or `NewAppScreen`.
    RnNoDeepImports,
    /// Importing removed core modules (`AsyncStorage`, `WebView`, `NetInfo`, `Clipboard`, etc.) from `react-native`.
    RnNoDeprecatedModules,
    /// Calling `Dimensions.get(...)` inside a component or hook instead of `useWindowDimensions()`.
    RnNoDimensionsGet,
    /// Numeric or string falsy `&&` short-circuit (`{count && <View />}`) that crashes when rendering `0` or `""` on React Native.
    RnNoFalsyAndRender,
    /// Passing children to React Native `<Image>` instead of `<ImageBackground>`.
    RnNoImageChildren,
    /// Passing an inline function to `renderItem` on a React Native virtualized list.
    RnNoInlineFlatlistRenderitem,
    /// Passing an inline object literal prop to a component inside list `renderItem`.
    RnNoInlineObjectInListItem,
    /// Importing unmaintained legacy Expo packages (`expo-av`, `expo-permissions`, `expo-app-loading`, `react-native-fast-image`).
    RnNoLegacyExpoPackages,
    /// Using platform-specific legacy shadow style properties (`shadowColor`, `elevation`, etc.).
    RnNoLegacyShadowStyles,
    /// Importing JS-driven `@react-navigation/stack` or `@react-navigation/drawer` instead of `@react-navigation/native-stack`.
    RnNoNonNativeNavigator,
    /// Importing `PanResponder` from `react-native` instead of `react-native-gesture-handler`.
    RnNoPanresponder,
    /// Redundant `key` prop on the root JSX element returned from list `renderItem`.
    RnNoRenderitemKey,
    /// Updating React state inside an `onScroll` handler on React Native.
    RnNoScrollState,
    /// Rendering an unbounded `.map()` list inside `<ScrollView>` instead of `FlatList` / `FlashList`.
    RnNoScrollviewMappedList,
    /// Retired rule: imperative `setNativeProps` calls in React Native.
    RnNoSetNativeProps,
    /// Retired rule: single-element style array in React Native.
    RnNoSingleElementStyleArray,
    /// Accessing `RN.Platform` via a `react-native` namespace import in Expo SDK 54+.
    RnPlatformShakingUseDirectImport,
    /// Retired rule: manual safe-area inset padding vs. `contentInsetAdjustmentBehavior`.
    RnPreferContentInsetAdjustment,
    /// Importing `Image` from `react-native` instead of `expo-image` in an Expo project.
    RnPreferExpoImage,
    /// Wrapping a simple single-tap `Gesture.Tap()` in `<GestureDetector>` instead of `<Pressable>`.
    RnPreferPressableOverGestureDetector,
    /// Importing legacy `Touchable*` components instead of `Pressable`.
    RnPreferPressable,
    /// Retired rule: importing `Animated` from `react-native` instead of `react-native-reanimated`.
    RnPreferReanimated,
    /// Mutating a Reanimated shared value inside `<Pressable>` JS press handlers instead of UI-thread `Gesture.Tap()`.
    RnPressableSharedValueMutation,
    /// Passing removed Reanimated 3 spring rest thresholds (`restDisplacementThreshold`, `restSpeedThreshold`) in Reanimated 4.
    RnReanimated4NoLegacySpringThresholds,
    /// Calling removed Reanimated 3 APIs (`useAnimatedGestureHandler`, `useWorkletCallback`, `combineTransition`, `addWhitelisted*Props`) in Reanimated 4.
    RnReanimated4NoRemovedApi,
    /// Calling worklet schedulers (`runOnUI`, `runOnJS`, `executeOnUIRuntimeSync`, `runOnRuntime`) from `react-native-reanimated` in Reanimated 4.
    RnReanimated4UseWorkletsScheduler,
    /// Dynamic `paddingTop` or `paddingBottom` on `ScrollView` `contentContainerStyle`.
    RnScrollviewDynamicPadding,
    /// Using `flex: 1` shorthand on `ScrollView` `contentContainerStyle` instead of `flexGrow: 1`.
    RnScrollviewFlexInContentContainer,
    /// Using legacy iOS/Android shadow style properties instead of unified CSS `boxShadow`.
    RnStylePreferBoxShadow,
    /// Referencing removed `module:metro-react-native-babel-preset` on React Native 0.73+.
    RnNoMetroBabelPreset,
    /// Using `module:@react-native/babel-preset` without an `enableBabelRuntime` version string.
    RnNoMetroBabelRuntimeVersion,
    /// Listing `react` or `react-native` in `dependencies` of a `react-native-builder-bob` library.
    RnLibraryReactInDependencies,
    /// Placing `babel-plugin-react-compiler` after other plugins in Babel `plugins`.
    RnReactCompilerPluginFirst,
    /// Using legacy `react-native-reanimated/plugin` or placing `react-native-worklets/plugin` non-last in Reanimated 4.
    RnReanimatedWorkletsPluginLast,
    /// Disabling `minifyEnabled` or `shrinkResources` in Android `buildTypes.release`.
    RnAndroidReleaseShrinkingDisabled,
    /// Declaring legacy `@unimodules/*` or `react-native-unimodules` dependencies in Expo.
    ExpoNoUnimodulesPackages,
    /// Declaring global CLIs (`expo-cli`, `eas-cli`) in project dependencies.
    ExpoNoCliDependencies,
    /// Declaring redundant or removed transitive Expo SDK packages directly in `package.json`.
    ExpoNoRedundantDependency,
    /// Overriding Expo SDK-critical packages (`metro`, `@expo/cli`, `@expo/metro-config`, etc.) via `overrides`/`resolutions`.
    ExpoNoConflictingDependencyOverride,
    /// Installing `@react-navigation/*` directly alongside `expo-router` on Expo SDK 56.
    ExpoRouterNoReactNavigation,
    /// Mixing scoped `@react-native-vector-icons/*` with `@expo/vector-icons` or `react-native-vector-icons` on Expo SDK 56+.
    ExpoVectorIconsConflict,
    /// Defining `expo`/`react-native` scripts or a package `name` that collides with a dependency in `package.json`.
    ExpoPackageJsonConflict,
    /// Missing or multiple package manager lockfiles at the Expo workspace root.
    ExpoLockfile,
    /// Custom `metro.config.*` in an Expo project that does not extend `expo/metro-config`.
    ExpoMetroConfig,
    /// Un-gitignored `.env*.local` files in an Expo repository.
    ExpoEnvLocalNotGitignored,
    /// Un-gitignored `.expo/` state directory or gitignored local module `modules/*/ios|android` native directories.
    ExpoGitignore,
    /// `newArchEnabled: false` in `app.json` while using Reanimated 4 or `react-native-worklets`.
    ExpoReanimatedV4RequiresNewArch,
    /// `updates.disableAntiBrickingMeasures: true` in `app.json`.
    ExpoUpdatesNoUnsafeProductionConfig,
    /// Mutating Zustand state in place and reusing the same reference in `set(...)` or `setState(...)`.
    ZustandNoMutatingState,
    /// Returning a fresh object or array from a Zustand store selector without `useShallow`.
    ZustandNoFreshSelectorResult,
    /// Calling Zustand `get()` synchronously during store initialization.
    ZustandNoGetDuringInitialization,
    /// Returning a fresh object or array from a Jotai derived `atom((get) => ...)`.
    JotaiDerivedAtomReturnsFreshObject,
    /// Subscribing directly to a `jotai-tanstack-query` `atomWithQuery` envelope atom in render.
    JotaiTqUseRawQueryAtom,
    /// Wrapping an already `memo`-ized or `observer`-wrapped component in MobX `observer(...)`.
    MobxNoObserverWrappedMemo,
    /// Calling `makeAutoObservable(this)` in a class that uses inheritance (`extends` or subclassed).
    MobxNoMakeAutoObservableInInheritance,
    /// Reading a Valtio proxy directly during render when `useSnapshot(proxy)` is active.
    ValtioNoProxyReadInRender,
    /// Using `onChange` instead of `onInput` on text-like `<input>` / `<textarea>` in pure Preact.
    PreactPreferOninput,
    /// Using `onDoubleClick` instead of `onDblClick` on host elements in pure Preact.
    PreactPreferOndblclick,
    /// Reading `render(props, state)` parameters in a Preact class component instead of `this.props` / `this.state`.
    PreactNoRenderArguments,
    /// Importing hooks from `'react'` instead of `'preact/hooks'` in pure Preact.
    PreactNoReactHooksImport,
    /// Accessing `.length` or array methods directly on `children` / `props.children` in Preact without `toChildArray`.
    PreactNoChildrenLength,
    /// Handling Ctrl-C in Ink `useInput` without passing `{ exitOnCtrlC: false }` to `render()`.
    InkCtrlCHandlerRequiresExitOption,
    /// Retired rule: `<Newline>` placement inside Ink `<Text>`.
    InkNewlineInsideText,
    /// Calling `process.exit()` directly inside an Ink `useInput` handler instead of `useApp().exit()`.
    InkNoBareProcessExit,
    /// Calling `useStdin().setRawMode()` synchronously during render in Ink.
    InkNoDirectRawMode,
    /// Rendering DOM host elements (`<div>`, `<span>`, etc.) inside an Ink terminal tree.
    InkNoDomHostElements,
    /// Using DOM-dependent router components (`BrowserRouter`, `HashRouter`, `Link` from `react-router-dom`) in Ink.
    InkNoDomRouter,
    /// Calling `useFocusManager().focus*()` synchronously during render in Ink.
    InkNoFocusInRender,
    /// Nesting Ink layout components (`<Box>`, `<Spacer>`, `<Static>`) inside `<Text>` or `<Transform>`.
    InkNoLayoutInsideText,
    /// Using live input hooks (`useInput`, `usePaste`) in a component rendered only via `renderToString()`.
    InkNoLiveHooksInRenderToString,
    /// Calling Ink `measureElement()` synchronously during render.
    InkNoMeasureElementInRender,
    /// Rendering multiple unconditional `<Static>` regions in a single Ink component root.
    InkNoMultipleStatic,
    /// Calling Ink `render()` repeatedly on the same output stream without unmounting or calling `rerender()`.
    InkNoRepeatedRender,
    /// Driving a manual `setInterval` frame counter in `useEffect` instead of Ink `useAnimation()`.
    InkPreferUseAnimation,
    /// Inferring paste events from `useInput` newline/length checks instead of Ink `usePaste()`.
    InkPreferUsePaste,
    /// Passing a reordered/mutated collection (`.sort()`, `.reverse()`, `.toSorted()`, `.toReversed()`) to Ink `<Static items={...}>`.
    InkStaticIsAppendOnly,
    /// Missing `key` prop on the root JSX element returned by an Ink `<Static>` render function.
    InkStaticRequiresKey,
    /// Retired rule: Ink `<Suspense>` concurrent rendering mode.
    InkSuspenseRequiresConcurrent,
    /// Reading `process.stdout.columns` or `process.stdout.rows` in Ink render without a resize listener or `useWindowSize()`.
    InkUseReactiveWindowSize,
    /// Using `.length` instead of `string-width` for horizontal cursor column offset in `useCursor().setCursorPosition()`.
    InkUseStringWidthForCursor,
    /// Spawning an interactive child process (`stdio: "inherit"`) inside Ink `useInput` without `useApp().suspendTerminal()`.
    InkUseSuspendTerminal,
    /// Using deprecated `z.string().email()` / `.uuid()` / `.url()` method chains instead of top-level Zod 4 format functions.
    ZodV4PreferTopLevelStringFormats,
    /// Using deprecated Zod 3 schema APIs (`z.nativeEnum`, `z.object().strict()`, `z.record(valueSchema)`, `z.function().args()`, etc.) in Zod 4.
    ZodV4NoDeprecatedSchemaApis,
    /// Using deprecated Zod 3 error customization (`invalid_type_error`, `required_error`, `errorMap`) in Zod 4.
    ZodV4NoDeprecatedErrorCustomization,
    /// Using removed `ZodError` APIs (`.flatten()`, `.format()`, `.formErrors`, `.errors`, `.addIssue()`, `ZodError.create()`) in Zod 4.
    ZodV4NoDeprecatedErrorApis,
    // --- Ticket 07 rules ---
    /// Updating a State Slot inside an Effect Node that tracks that same State Slot without converging.
    NoSelfUpdatingEffect,
    /// Calling a state setter unconditionally at the top level of a component render body.
    NoSetStateInRender,
    /// Calling a state setter after an `await` inside `useEffect` without a cancellation guard.
    NoSetStateAfterAwaitInEffect,
    /// Reading or writing `ref.current` during component render.
    NoRefCurrentInRender,
    /// Invoking a prop callback directly during component render.
    NoPropCallbackInRender,
    /// Synchronously invoking a prop callback inside `useEffect`.
    NoPropCallbackInEffect,
    /// Performing side effects inside a `setState(prev => ...)` updater callback.
    NoSideEffectInStateUpdaterFunction,
    /// Reading a stale timer ref or failing to clear/store a timer ref properly.
    NoStaleTimerRef,
    /// Clearing an async error state unconditionally before an unowned async operation.
    NoUnownedAsyncErrorClear,
    /// Listing a whole object in hook dependencies when only specific properties are read.
    NoWholeObjectDepWithMemberReads,
    /// Spreading props after default properties in an object literal (`{ a: 1, ...props }`).
    NoSpreadPropsOverDefaultsClobbersWithUndefined,
    /// Component manages many coupled `useState` slots that should be consolidated into `useReducer`.
    PreferUseReducer,
    /// Effect reads a reactive value only for logging/event notification and re-runs unnecessarily.
    PreferUseEffectEvent,
    /// Calling `setState(state + 1)` with direct state read instead of functional updater `setState(s => s + 1)`.
    RerenderFunctionalSetstate,
    /// Passing an expensive call expression directly to `useState(expensive())` instead of `useState(() => expensive())`.
    RerenderLazyStateInit,
    /// Passing an expensive construction directly to `useRef(new Expensive())` on every render.
    RerenderLazyRefInit,
    /// State Slot is only read inside event handlers and never affects rendered output.
    RerenderStateOnlyInHandlers,
    /// Calling a hook whose return value is only used after an early return or inside callbacks.
    RerenderDeferReadsHook,
    /// Passing unstable or overly broad dependencies to an effect or memo hook.
    RerenderDependencies,
    /// Registering an event listener, timer, or subscription in `useEffect` without a cleanup return.
    EffectNeedsCleanup,
    /// Calling a React Hook conditionally, in a loop, or outside a component/custom hook.
    RulesOfHooks,
    /// `<input checked>` without `onChange` or `readOnly`, or mixing `checked` with `defaultChecked`.
    CheckedRequiresOnchangeOrReadonly,
    /// `<button>` inside a form or with invalid/missing explicit `type` attribute.
    ButtonHasType,
    /// Redundant `<></>` or `<Fragment>` wrapping a single child or empty content.
    JsxNoUselessFragment,
    /// Explicit `={true}` on a boolean JSX attribute (`<Comp disabled={true} />`).
    JsxBooleanValue,
    /// Unnecessary curly braces around a string literal in JSX (`<Comp title={"hello"} />`).
    JsxCurlyBracePresence,
    /// Using `<React.Fragment>` instead of shorthand `<>...</>` when no `key` is present.
    JsxFragments,
    /// User-defined JSX component name not using PascalCase (`<my_component />`).
    JsxPascalCase,
    /// Spreading arbitrary props onto a JSX element (`<Comp {...props} />`).
    JsxPropsNoSpreading,
    /// JSX nesting depth exceeds configured maximum depth.
    JsxMaxDepth,
    /// Non-void JSX element with no children written with a closing tag (`<Comp></Comp>`).
    SelfClosingComp,
    /// `style` attribute on JSX element is not an object expression (`style="color: red"`).
    StylePropObject,
    /// Unknown or non-standard DOM property on an intrinsic JSX element (`<div class="foo" />`).
    NoUnknownProperty,
    /// Defining a nested component inside another component (`no-unstable-nested-components`).
    NoUnstableNestedComponents,
    /// Non-standard or asymmetric `[val, setVal] = useState()` naming.
    HookUseState,
    /// Component wrapped in `memo` or `forwardRef` missing a `displayName` or named function.
    DisplayName,
    /// Legacy string `ref="myRef"` on a JSX element.
    NoStringRefs,
    /// Usage of `UNSAFE_componentWillMount`, `UNSAFE_componentWillReceiveProps`, or `UNSAFE_componentWillUpdate`.
    NoUnsafe,
    /// Calling `this.setState` inside `componentDidMount`.
    NoDidMountSetState,
    /// Calling `this.setState` inside `componentDidUpdate`.
    NoDidUpdateSetState,
    /// Calling `this.setState` inside `componentWillUpdate`.
    NoWillUpdateSetState,
    /// Initializing state outside constructor or both in constructor and class property.
    StateInConstructor,
    /// Using `createReactClass` instead of ES6 `class extends React.Component`.
    PreferEs6Class,
    /// Stateless class component that can be written as a function component.
    PreferFunctionComponent,
    /// Passing a freshly allocated array or `.filter()`/`.map()`/`.concat()` result as a JSX prop.
    JsxNoNewArrayAsProp,
    /// Passing an inline arrow/function expression or `.bind()` as a JSX prop.
    JsxNoNewFunctionAsProp,
    /// Using `Math.random()`, `Date.now()`, `crypto.randomUUID()`, or `nanoid()` in a JSX `key`.
    NoRandomKey,
    /// Numeric expression before `&&` in JSX (`{items.length && <List />}`) rendering a stray `0`.
    RenderingConditionalRender,
    /// Calling `event.preventDefault()` in an invalid or passive handler context.
    NoPreventDefault,
    /// Invalid `offset` values in Web Animations API `element.animate(keyframes)`.
    WebAnimationOffsetsValid,
    /// Mixing controlled `value` and uncontrolled `defaultValue` or passing `value={undefined}`.
    NoUncontrolledInput,
    /// Constant literal in logical `||` / `&&` comparison chain (`x === 'a' || 'b'`).
    NoCollapsedLiteralOrChainAsValue,
    /// Consuming `await response.json()` without checking `response.ok` or `response.status`.
    NoFetchResponseUsedWithoutStatusCheck,
    /// Calling `.sort()`, `.reverse()`, or `.splice()` directly on a prop or hook result array.
    NoMutatingArrayMethodOnPropOrHookResult,
    /// Nesting `<form>` inside another `<form>`.
    HtmlNoNestedForm,
    /// Placing `<tr>` directly inside `<table>` without `<thead>`, `<tbody>`, or `<tfoot>`.
    HtmlNoInvalidTableNesting,
    /// Defining a React component inside another component's body.
    NoNestedComponentDefinition,
    /// Static array or object literal declared inside a component body instead of module scope.
    PreferModuleScopeStaticValue,
    /// Pure helper function with no component-local captures declared inside a component body.
    PreferModuleScopePureFunction,
    /// Manual `useMemo`/`useCallback`/`memo` when React Compiler is active.
    ReactCompilerNoManualMemoization,
    /// Assigning `.defaultProps` on a function component instead of using default parameters.
    NoDefaultProps,
    /// Assigning `.propTypes` instead of TypeScript prop types.
    NoPropTypes,
    /// Using legacy React `contextTypes`, `childContextTypes`, or `getChildContext`.
    NoLegacyContextApi,
    /// Using legacy `componentWillMount`, `componentWillReceiveProps`, or `componentWillUpdate`.
    NoLegacyClassLifecycles,
    /// Invoking a higher-order component factory inside a render body.
    NoInlineHocOnComponent,
    /// Component exceeds maintainable line/statement complexity size.
    NoGiantComponent,
    /// React component or hook exceeds cyclomatic/branching complexity threshold.
    NoHighComplexityReactFunction,
    /// Component accepts too many boolean flag props instead of explicit variants.
    NoManyBooleanProps,
    /// Generic handler name (`handleClick`, `onChange`) that obscures domain intent.
    NoGenericHandlerNames,
    /// Calling a `renderFoo()` helper function inside JSX instead of extracting a child component.
    NoRenderInRender,
    /// Using APIs deprecated in React 19 (`forwardRef`, `React.createFactory`, `defaultProps`).
    NoReact19DeprecatedApis,
    /// Using deprecated `react-dom` APIs (`ReactDOM.render`, `ReactDOM.hydrate`, `findDOMNode`).
    NoReactDomDeprecatedApis,
    /// `Context.Provider` bundles frequently mutated State Slots with static fields read by static-only consumers.
    OverloadedContextProvider,
    /// Subject invoking suspending hooks/APIs or throwing boundaries lacks an ancestral `<Suspense>` or `<ErrorBoundary>` across Caller Sites.
    MissingSuspenseOrErrorBoundary,
    /// Activity wraps an effect-heavy subtree.
    ActivityWrapsEffectHeavySubtree,
    /// Listener re-subscribes on every handler change.
    AdvancedEventHandlerRefs,
    /// Base UI tab is outside Tabs.List.
    BaseUiTabsTabRequiresList,
    /// Class component acquires a resource with no teardown.
    ClassComponentMissingComponentWillUnmountTeardown,
    /// Memoized debounce never cancelled on unmount.
    DebounceNoCleanup,
    /// Effect cleanup does not match its event listener.
    EffectListenerCleanupMismatch,
    /// Effect cleanup removes the wrong listener reference.
    EffectListenerCleanupReferenceMismatch,
    /// Observer created in an effect never disconnected.
    EffectObserverNeedsDisconnect,
    /// requestAnimationFrame loop never cancelled.
    EffectRafLoopNeedsCancel,
    /// removeEventListener called with a fresh inline handler.
    EffectRemoveListenerInlineHandler,
    /// Blocked component prop bypasses API contract.
    ForbidComponentProps,
    /// Blocked DOM prop bypasses project contract.
    ForbidDomProps,
    /// Blocked element bypasses approved UI primitives.
    ForbidElements,
    /// forwardRef without ref parameter.
    ForwardRefUsesRef,
    /// Hook import alias disables hook lint checks.
    HookImportRenameLosesUsePrefix,
    /// NaN in a hook dependency array.
    HooksNoNanInDeps,
    /// Label wraps multiple native controls.
    HtmlLabelHasSingleControl,
    /// Block element inside a paragraph.
    HtmlNoInvalidParagraphChild,
    /// JSX in disallowed file extension.
    JsxFilenameExtension,
    /// Comment rendered as JSX text.
    JsxNoCommentTextnodes,
    /// Duplicate props on element.
    JsxNoDuplicateProps,
    /// JSX element passed as a prop.
    JsxNoJsxAsProp,
    /// Same prop spread multiple times.
    JsxPropsNoSpreadMulti,
    /// AnimatePresence unmounts with its exiting child.
    MotionAnimatePresenceMustOutliveChild,
    /// AnimatePresence child is missing a key.
    MotionAnimatePresenceRequiresKey,
    /// AnimatePresence wait mode has multiple children.
    MotionAnimatePresenceWaitSingleChild,
    /// Motion component is created during render.
    MotionCreateInRender,
    /// Motion drag constraints do not match the drag axis.
    MotionDragAxisConstraintMismatch,
    /// Imperative Motion animation runs during render.
    MotionImperativeAnimationInRender,
    /// Motion keyframes and times have different lengths.
    MotionKeyframeTimesMismatch,
    /// Motion layout animation targets an inline element.
    MotionLayoutOnInlineElement,
    /// Motion layout ID is unstable in an iteration.
    MotionUnstableLayoutIdInIteration,
    /// Motion transform ranges have different lengths.
    MotionUseTransformRangeLength,
    /// Motion value subscription is created during render.
    MotionValueSubscriptionInRender,
    /// Multiplicative math on optional-chained value can be NaN.
    NoArithmeticOnOptionalChainedOperand,
    /// Unguarded member access on find() result.
    NoArrayFindResultMemberAccessWithoutGuard,
    /// Array index result dereferenced without a guard.
    NoArrayIndexDerefWithoutBoundsOrEmptyGuard,
    /// Async effect callback.
    NoAsyncEffectCallback,
    /// Async mutating handler without re-entry guard.
    NoAsyncEventHandlerWithoutReentryGuard,
    /// Boolean toggle reads a stale value.
    NoBooleanToggleWithoutFunctionalUpdate,
    /// Component called as a function.
    NoCallComponentAsFunction,
    /// Multiple setState calls in one effect.
    NoCascadingSetState,
    /// Children passed as a prop.
    NoChildrenProp,
    /// cloneElement makes child props fragile.
    NoCloneElement,
    /// Request failure rendered as an empty result.
    NoCollapseRequestErrorToEmptyState,
    /// createContext called during render.
    NoCreateContextInRender,
    /// Object URL is created during render.
    NoCreateObjectUrlInRender,
    /// createRef in function component.
    NoCreateRefInFunctionComponent,
    /// Store created during render.
    NoCreateStoreInRender,
    /// Deprecated KeyboardEvent keyCode or which.
    NoDeprecatedKeyboardEventKeycodeWhich,
    /// Effect Event listed in effect deps.
    NoEffectEventInDeps,
    /// Effect dependency recreated every render.
    NoEffectWithFreshDeps,
    /// Effect wrapper discards forwarded cleanup return.
    NoEffectWrapperDiscardsCallbackCleanupReturn,
    /// Enter submit without IME composition guard.
    NoEnterSubmitWithoutImeCompositionGuard,
    /// fill().map() first param is the element, not the index.
    NoFillMapElementAsKey,
    /// findDOMNode breaks component encapsulation.
    NoFindDomNode,
    /// Floating .then in a JSX event handler.
    NoFloatingThenInJsxHandler,
    /// Nondeterministic built-in at module scope.
    NoImpureCallAtModuleScope,
    /// State updater has side effects.
    NoImpureStateUpdater,
    /// Indeterminate checkbox state set as an attribute.
    NoIndeterminateAttribute,
    /// isMounted lets async callbacks update after unmount.
    NoIsMounted,
    /// No JSX.Element.
    NoJsxElementType,
    /// Loading flag reset outside finally.
    NoLoadingFlagResetOutsideFinally,
    /// srcSet mixes width and density descriptors.
    NoMixedSrcsetDescriptors,
    /// Multiple components in one file.
    NoMultiComp,
    /// Crowded component file.
    NoMultiComponentFile,
    /// Mutable value in effect dependencies.
    NoMutableInDeps,
    /// Mutating a queried DOM node this component renders.
    NoMutateQueriedDomNodeInComponent,
    /// State mutated in place then set by same reference.
    NoMutateThenSetOrReturnSameReference,
    /// Reducer mutates its state.
    NoMutatingReducerState,
    /// Namespaced JSX element.
    NoNamespace,
    /// Unguarded querySelector with href-derived selector.
    NoNonLiteralSelectorQueryWithoutTryCatch,
    /// Non-null assertion on a maybe-undefined result.
    NoNonNullAssertionOnMaybeUndefinedResult,
    /// Nondeterministic id generated in render body.
    NoNondeterministicIdValueInRenderBody,
    /// Nullish coalescing swallowed by adjacent arithmetic.
    NoNullishCoalescingArithmeticPrecedence,
    /// Object.keys/values/entries on maybe-undefined value.
    NoObjectKeysValuesEntriesOnMaybeUndefined,
    /// Object or lossy array coerced in a template literal.
    NoObjectOrArrayCoercedToStringInTemplateLiteral,
    /// Passive owner ref leaves a stale-request window.
    NoPassiveRequestOwnerRef,
    /// Children type checked at runtime.
    NoPolymorphicChildren,
    /// Predicate function used without calling it.
    NoPredicateFunctionReferenceInBooleanPosition,
    /// Effect promise .then sets state with no catch.
    NoPromiseThenSideEffectInEffectWithoutCatch,
    /// React.Children is fragile when child shape changes.
    NoReactChildren,
    /// Redundant shouldComponentUpdate.
    NoRedundantShouldComponentUpdate,
    /// Ref cleanup requires React 19.
    #[serde(rename = "no-ref-callback-cleanup-before-react-19")]
    NoRefCallbackCleanupBeforeReact19,
    /// Using ReactDOM.render return value.
    NoRenderReturnValue,
    /// Local class state forbidden.
    NoSetState,
    /// String true/false on a boolean attribute.
    NoStringFalseOnBooleanAttribute,
    /// this used in function component.
    NoThisInSfc,
    /// Unescaped dynamic string in RegExp constructor.
    NoUnescapedDynamicStringInRegexp,
    /// Unescaped entities in JSX.
    NoUnescapedEntities,
    /// Browser global read at module scope.
    NoUnguardedBrowserGlobalAtModuleScope,
    /// Unguarded numeric parse of an input value.
    NoUnguardedNumericInputParse,
    /// Unguarded call to a throwing parse API.
    NoUnguardedThrowingParseCall,
    /// Unsafe JSON.parse dereference.
    NoUnsafeJsonParse,
    /// Whole-object param default loses per-key defaults.
    NoWholeObjectDefaultLosingPerKeyDefaults,
    /// Captured pointer interaction has no cancellation path.
    PointerCaptureNeedsCancelHandler,
    /// Radix tabs trigger is outside Tabs.List.
    RadixTabsTriggerRequiresList,
    /// React not in scope for JSX.
    ReactInJsxScope,
    /// Parent path cannot match descendant routes.
    ReactRouterDescendantRoutesRequireSplat,
    /// Aborted requests are reported as errors.
    ReactRouterGuardAbortedHandleError,
    /// Internal route uses a document navigation.
    ReactRouterInternalRouteAnchor,
    /// Nested routes have no Outlet.
    ReactRouterNestedRouteRequiresOutlet,
    /// Middleware catch cannot observe downstream errors.
    ReactRouterNoCatchMiddlewareNext,
    /// Client-only module rendered on the server.
    ReactRouterNoClientModuleInServerRender,
    /// Duplicate route ID.
    ReactRouterNoDuplicateRouteId,
    /// Leaf route renders nothing.
    ReactRouterNoEmptyLeafRoute,
    /// Absolute child path escapes its parent.
    ReactRouterNoInvalidAbsoluteChildPath,
    /// Immutable route property returned from lazy.
    ReactRouterNoInvalidLazyRouteProperties,
    /// Invalid splat route path.
    ReactRouterNoInvalidSplatPath,
    /// Loader reads a request body.
    ReactRouterNoLoaderRequestBody,
    /// Middleware consumes the outgoing response body.
    ReactRouterNoMiddlewareResponseBodyConsumption,
    /// Multiple blockers in one component.
    ReactRouterNoMultipleBlockers,
    /// Middleware continuation called twice.
    ReactRouterNoMultipleMiddlewareNext,
    /// Search params updated multiple times.
    ReactRouterNoMultipleSetSearchParamsInTick,
    /// navigate() called during render.
    ReactRouterNoNavigateInRender,
    /// Router nested inside another router.
    ReactRouterNoNestedRouter,
    /// redirect() inside try-catch.
    ReactRouterNoRedirectInTryCatch,
    /// Route module has an environment suffix.
    ReactRouterNoRouteModuleEnvironmentSuffix,
    /// Router created during render.
    ReactRouterNoRouterInRender,
    /// Loader mutates session state.
    ReactRouterNoSessionMutationInLoader,
    /// Cookie expiry is fixed at module load.
    ReactRouterNoStaticCookieExpires,
    /// Search params mutated without navigation.
    ReactRouterNoUnsynchronizedSearchParamsMutation,
    /// Error UI assumes loader data exists.
    ReactRouterNoUseLoaderDataInErrorUi,
    /// Root route lacks an error boundary.
    ReactRouterRequireRootErrorBoundary,
    /// Resource link intercepted as navigation.
    ReactRouterResourceLinkRequiresReload,
    /// Transition drops a navigation promise.
    ReactRouterReturnNavigationPromiseInTransition,
    /// Server middleware drops the Response.
    ReactRouterServerMiddlewareReturnResponse,
    /// Session mutation is not committed.
    ReactRouterSessionMutationRequiresCommit,
    /// Removed meta data field.
    ReactRouterV8NoMetaDataField,
    /// Removed react-router-dom import.
    ReactRouterV8NoReactRouterDomImport,
    /// Removed React Router future flag.
    ReactRouterV8NoRemovedFutureFlags,
    /// Contradictory route object.
    ReactRouterValidRouteObject,
    /// useSelector derives data inline.
    ReduxUseselectorInlineDerivation,
    /// useSelector returns a new collection.
    ReduxUseselectorReturnsNewCollection,
    /// calculateMetadata fetch ignores abortSignal.
    RemotionCalculateMetadataFetchSignal,
    /// Randomness changes between rendered frames.
    RemotionDeterministicRandomness,
    /// CSS animation is not frame-driven.
    RemotionNoCssAnimation,
    /// CSS transition is not frame-driven.
    RemotionNoCssTransition,
    /// CSS URL asset can flicker in Remotion.
    RemotionNoCssUrlAssets,
    /// Module-scoped delayRender blocks every composition.
    RemotionNoModuleScopeDelayRender,
    /// Native media element bypasses Remotion loading.
    RemotionNoNativeMediaElements,
    /// Next.js Image can flicker in Remotion.
    RemotionNoNextImage,
    /// delayRender handle is recreated during render.
    RemotionStableDelayRenderHandle,
    /// Overly precise SVG path values.
    RenderingSvgPrecision,
    /// Render method does not return.
    RequireRenderReturn,
    /// Command item styled by presence-only state variant.
    ShadcnCommandItemStateVariantRequiresValue,
    /// Raw control directly inside InputGroup.
    ShadcnInputGroupNoRawControls,
    /// Tabs trigger is outside TabsList.
    ShadcnTabsTriggerRequiresList,
    /// Non-transient custom prop on styled intrinsic element.
    StyledComponentsNonTransientCustomPropOnIntrinsicElement,
    /// Form submit reloads the page around handleSubmit.
    TanstackFormOnSubmitRequiresPreventDefault,
    /// Table data or columns recreated every render.
    TanstackTableNoUnstableDataOrColumns,
    /// Measured virtual item without data-index.
    TanstackVirtualMeasureElementRequiresDataIndex,
    /// Children on a void element.
    VoidDomElementsNoChildren,
    /// Web Animation starts during render.
    WaapiAnimationInRender,
    /// WritableSignal mutated inside Angular `effect()` instead of `computed()`.
    AngularNoSignalWriteInEffect,
    /// RxJS `.subscribe()` without `takeUntilDestroyed()` or `ngOnDestroy` teardown.
    AngularRxjsSubscribeRequiresTeardown,
    /// `@Component` decorator missing `changeDetection: ChangeDetectionStrategy.OnPush`.
    AngularPreferOnPushChangeDetection,
    /// Unstable `@for (...; track)` expression using `$index` or raw object identity.
    AngularForTrackNoIndex,
    /// Heavy side effects, HTTP requests, or subscriptions inside Angular `constructor()`.
    AngularNoWorkInConstructor,
    /// Nested RxJS `.subscribe()` call instead of `switchMap` / `mergeMap` / `concatMap` / `exhaustMap`.
    AngularNoNestedSubscribe,
    /// Direct DOM mutation on `ElementRef.nativeElement` instead of bindings or `Renderer2`.
    AngularNoDirectNativeElementMutation,
    /// Unchecked `.unwrap()` or `.expect()` call in production Rust code.
    RsNoUnwrapInProduction,
    /// Direct slice or `Vec` indexing `slice[idx]` without prior bounds guard.
    RsNoUnguardedSliceIndex,
    /// Potentially lossy or sign-changing numeric `as` cast.
    RsNoLossyNumericAsCast,
    /// `unsafe` block or `unsafe impl` missing a `// SAFETY:` invariant comment.
    RsRequireSafetyCommentOnUnsafe,
    /// `std::mem::forget` or `core::mem::forget` call that leaks resources.
    RsNoMemForget,
    /// Mutable default argument in function definition.
    PyNoMutableDefaultArg,
    /// Broad or bare except block silently swallows exceptions.
    PyNoSilentBroadExcept,
    /// File or database resource acquired without a with context manager.
    PyRequireContextManagerForResource,
    /// Unguarded parse call or dictionary key indexing on untrusted input.
    PyNoUnguardedParseOrKeyAccess,
    /// Naive datetime.now() or datetime.utcnow() call without explicit timezone.
    PyRequireTimezoneAwareDatetime,
    /// Pydantic or dataclass field using mutable or runtime-call default instead of `default_factory`.
    PyPydanticPreferDefaultFactory,
    /// FastAPI route handler missing both `response_model` and an explicit typed return annotation.
    PyFastapiRequireResponseModel,
    /// State-mutating FastAPI route (`POST`/`PUT`/`PATCH`/`DELETE`) missing an authentication dependency.
    PyFastapiMutatingRouteRequiresAuth,
    /// SQLAlchemy or Django ORM query executed inside a `for` or `while` loop (N+1 query hazard).
    PyOrmNoQueryInLoop,
    /// Raw f-string, `.format()`, `%`, or `+` SQL string interpolation passed to an execution sink.
    PySecurityNoRawSqlInterpolation,
    /// Unsafe deserialization (`pickle.loads`, `yaml.load` without `SafeLoader`) or shell execution (`shell=True`, `eval`, `exec`, `os.system`).
    PySecurityNoUnsafeDeserializationOrShell,
    /// Synchronous blocking call inside an `async def` coroutine.
    PyAsyncNoBlockingCall,
    /// Sequential `await` inside a `for` loop over independent coroutines.
    PyAsyncNoSequentialAwaitInLoop,
    /// Coroutine function called without `await` or task scheduling.
    PyAsyncNoUnawaitedCoroutine,
    /// `asyncio.create_task` or `loop.create_task` called without retaining a strong reference.
    PyAsyncNoFireAndForgetTask,
    /// Constant `re.compile(...)` called inside a function, method, or loop instead of module scope.
    PyPerfHoistRegex,
    /// Linear `in` membership check against a `list` inside a loop.
    PyPerfNoLinearMembershipInLoop,
    /// Circular module import cycle across the Python package graph.
    PyArchNoCircularImports,
    /// Public top-level Python symbol never imported or referenced across the package.
    PyArchNoUnusedExports,
    /// SQLx query built with `format!(...)` string interpolation instead of `$1` / `?` `.bind(...)` parameters.
    RsSqlxNoFormattedQueryString,
    /// SQLx query executed sequentially inside a `for`, `while`, or `loop` body (N+1 query hazard).
    RsSqlxNoQueryInLoop,
    /// Axum `State<...>` wrapping `Arc<Mutex<...>>` or contended `Mutex` state that serializes concurrent requests.
    RsAxumNoContendedMutexState,
    /// Reactive signal write inside a Leptos/Dioxus effect (`create_effect`, `Effect::new`, `use_effect`) deriving state from another signal.
    RsUiNoDerivedSignalInEffect,
    /// Function or method declaring 3 or more `bool` parameters (or 2+ consecutive `bool` parameters on public APIs).
    RsArchNoManyBooleanParams,
    /// `pub(crate)` item never referenced or imported by any other module or file in the crate.
    RsArchNoUnusedPubCrateItems,
    /// Holding a `std::sync::MutexGuard` or `RwLock` guard across an `.await` point.
    RsTokioNoStdLockAcrossAwait,
    /// Synchronous blocking call (`std::thread::sleep`, `std::fs`, `std::net`) inside an `async` context.
    RsTokioNoBlockingInAsync,
    /// `tokio::sync::mpsc::unbounded_channel` used without bounded backpressure.
    RsTokioPreferBoundedChannel,
    /// Heap allocation `.clone()` inside a hot `for`, `while`, or `loop` body.
    RsPerfNoCloneInLoop,
    /// `Regex::new(...)` compiled repeatedly inside a function or loop instead of `std::sync::LazyLock`.
    RsPerfHoistRegexToLazylock,
    /// `Vec::new()` followed by an unconditional `for` loop of `.push(...)` without `Vec::with_capacity`.
    RsPerfPreferVecWithCapacity,
    /// Unnecessary `format!(...)` allocation on a plain literal or single string argument.
    RsPerfNoUnnecessaryFormat,
    /// Binary or service entrypoint embeds domain logic, direct I/O, or rendering instead of thin adapter delegation.
    ArchThinEntrypoint,
    /// Single module interleaves database/filesystem/network I/O with terminal or UI presentation.
    ArchNoMixedIoAndPresentation,
    /// Module combines core domain type definitions with a large static data catalog.
    ArchSeparateStaticCatalogFromTypes,
    /// Monolithic module combines unrelated domain symbol clusters and responsibilities.
    ArchNoMixedDomainMonolith,
    /// Raw ANSI escape sequences or Unicode box-drawing literals constructed inline outside the terminal UI kit.
    ArchNoInlineTerminalUiPrimitives,
    /// Multi-field struct, class, or object constructed repeatedly via boilerplate literals instead of a fluent builder.
    ArchPreferFluentBuilder,
    /// Private helper function with identical normalized AST fingerprint duplicated across sibling modules.
    ArchNoDuplicatedHelperLogic,
    /// Internal Rust submodule declared as `pub mod` when the crate root already re-exports its public API surface.
    RsArchPreferPubCrateModules,
    /// Legacy `<dir>/mod.rs` directory module file used instead of modern `<dir>.rs` layout.
    RsArchNoLegacyModRs,
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
        &super::catalog::RULE_REGISTRY[self as usize]
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
        let without_prefix = trimmed.strip_prefix("dotore/").unwrap_or(trimmed);
        for meta in super::catalog::RULE_REGISTRY {
            if meta.canonical_id == without_prefix
                || meta.qualified_key == trimmed
                || meta.legacy_aliases.contains(&trimmed)
                || meta.legacy_aliases.contains(&without_prefix)
            {
                return Some(meta.id);
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
        )
    }
}

/// A single byte-range replacement in a source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteEdit {
    /// Optional target file path for cross-file rewrites (`None` targets the diagnostic's own file).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// Byte span in the original file to replace.
    pub span: ByteSpan,
    /// Replacement source text.
    pub replacement: String,
}

impl ByteEdit {
    /// Creates a byte-range replacement edit in the diagnostic's own file (`file: None`).
    #[must_use]
    pub fn new(span: ByteSpan, replacement: impl Into<String>) -> Self {
        Self::replace(span, replacement)
    }

    /// Creates a byte-range replacement edit in the diagnostic's own file (`file: None`).
    #[must_use]
    pub fn replace(span: ByteSpan, replacement: impl Into<String>) -> Self {
        Self {
            file: None,
            span,
            replacement: replacement.into(),
        }
    }

    /// Creates a byte-range deletion edit (`replacement: ""`) in the diagnostic's own file.
    #[must_use]
    pub fn delete(span: ByteSpan) -> Self {
        Self {
            file: None,
            span,
            replacement: String::new(),
        }
    }

    /// Creates a zero-length insertion edit at `offset` in the diagnostic's own file.
    #[must_use]
    pub fn insert(offset: u32, text: impl Into<String>) -> Self {
        Self {
            file: None,
            span: ByteSpan {
                start: offset,
                end: offset,
            },
            replacement: text.into(),
        }
    }

    /// Targets this byte edit at a specific file path for cross-file rewrites.
    #[must_use]
    pub fn in_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Sets an optional target file path for this byte edit.
    #[must_use]
    pub fn with_file(mut self, file: Option<PathBuf>) -> Self {
        self.file = file;
        self
    }
}

/// Deterministic patch for an `Autofix`-tier diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofixPatch {
    /// Summary of the transformation.
    pub description: String,
    /// Non-overlapping byte edits to apply to the file(s).
    pub edits: Vec<ByteEdit>,
}

impl AutofixPatch {
    /// Creates an empty [`AutofixPatch`] with the given `description`.
    #[must_use]
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            edits: Vec::new(),
        }
    }

    /// Alias for [`AutofixPatch::new`] starting a fluent patch builder.
    #[must_use]
    pub fn builder(description: impl Into<String>) -> Self {
        Self::new(description)
    }

    /// Creates a single-edit [`AutofixPatch`] replacing `span` with `replacement`.
    #[must_use]
    pub fn replace(
        description: impl Into<String>,
        span: ByteSpan,
        replacement: impl Into<String>,
    ) -> Self {
        Self {
            description: description.into(),
            edits: vec![ByteEdit::replace(span, replacement)],
        }
    }

    /// Creates a single-edit [`AutofixPatch`] deleting `span`.
    #[must_use]
    pub fn delete(description: impl Into<String>, span: ByteSpan) -> Self {
        Self {
            description: description.into(),
            edits: vec![ByteEdit::delete(span)],
        }
    }

    /// Creates a single-edit [`AutofixPatch`] inserting `text` at `offset`.
    #[must_use]
    pub fn insert(description: impl Into<String>, offset: u32, text: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            edits: vec![ByteEdit::insert(offset, text)],
        }
    }

    /// Appends a same-file byte replacement edit to this patch.
    #[must_use]
    pub fn with_edit(mut self, span: ByteSpan, replacement: impl Into<String>) -> Self {
        self.edits.push(ByteEdit::replace(span, replacement));
        self
    }

    /// Appends a cross-file byte replacement edit to this patch.
    #[must_use]
    pub fn with_file_edit(
        mut self,
        file: impl Into<PathBuf>,
        span: ByteSpan,
        replacement: impl Into<String>,
    ) -> Self {
        self.edits
            .push(ByteEdit::replace(span, replacement).in_file(file));
        self
    }

    /// Appends a pre-constructed [`ByteEdit`] to this patch.
    #[must_use]
    pub fn with_byte_edit(mut self, edit: ByteEdit) -> Self {
        self.edits.push(edit);
        self
    }

    /// Appends multiple [`ByteEdit`] items to this patch.
    #[must_use]
    pub fn with_edits(mut self, edits: impl IntoIterator<Item = ByteEdit>) -> Self {
        self.edits.extend(edits);
        self
    }
}

/// Priority tier (`P0`–`P3`) derived from static **Blast Radius** evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BlastRadiusTier {
    /// Critical runtime bugs, security flaws, 60fps frame-loop allocations/state updates, or deep **Render Cascades** with high fan-out.
    P0,
    /// High-impact `Error` diagnostics, multi-pass **Render Cascades**, or list/loop performance flaws.
    P1,
    /// Moderate `Surgical` or `Refactor` warnings or localized component issues.
    P2,
    /// Minor polish, dead-code cleanup, or low-fan-out maintainability hints.
    P3,
}

impl BlastRadiusTier {
    /// Canonical string representation (`"P0"`..=`"P3"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P0 => "P0",
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
        }
    }
}

/// Static render frequency context of a **Subject** or JSX site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenderFrequency {
    /// Standard component render pass (`1x`).
    Standard,
    /// Rendered inside a `.map()` or loop (`2x`).
    ListLoop,
    /// Executed inside a 60fps `useFrame` or `requestAnimationFrame` callback (`4x`).
    FrameLoop60Fps,
}

impl RenderFrequency {
    /// Canonical kebab-case string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::ListLoop => "list-loop",
            Self::FrameLoop60Fps => "frame-loop-60-fps",
        }
    }
}

/// Deterministic static runtime impact of a **Root-Cause Group** (see `GLOSSARY.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Deterministic composite score (`>= 1`).
    pub score: u32,
    /// Priority tier (`P0`–`P3`).
    pub tier: BlastRadiusTier,
    /// Render frequency classification (`standard`, `list-loop`, `frame-loop-60-fps`).
    pub render_frequency: RenderFrequency,
    /// Cross-file or cross-component fan-out (**Caller Sites**, child **Subjects**, or context consumers).
    pub fan_out: usize,
    /// Number of extra post-render passes or steps in the **Render Cascade**.
    pub cascade_depth: usize,
    /// Number of individual diagnostic sites clustered in this **Root-Cause Group**.
    pub site_count: usize,
    /// Number of distinct files touched by this **Root-Cause Group** (including **Caller Sites**).
    pub file_count: usize,
}

/// Verbatim source slice with 1-based line bounds attached to a [`FixCapsule`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceExcerpt {
    /// File path of the excerpt.
    pub file: PathBuf,
    /// 1-based inclusive start line.
    pub start_line: u32,
    /// 1-based inclusive end line.
    pub end_line: u32,
    /// Verbatim source slice.
    pub source: String,
}

/// Self-contained remediation unit emitted for a `Surgical` or `Refactor` **Root-Cause Group** (see `GLOSSARY.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixCapsule {
    /// Deterministic **Root-Cause Group** identifier.
    pub root_cause_group_id: String,
    /// Rule identifier.
    pub rule: RuleId,
    /// **Prescription Tier** (`Surgical` or `Refactor`).
    pub tier: PrescriptionTier,
    /// Static **Blast Radius** score and priority tier.
    pub blast_radius: BlastRadius,
    /// Verbatim source excerpt of the owning **Subject** (or diagnostic site).
    pub subject_excerpt: SourceExcerpt,
    /// Verbatim source excerpts of resolved cross-file **Caller Sites**.
    pub caller_site_excerpts: Vec<SourceExcerpt>,
    /// Compiled-in canonical transformation recipe in Markdown.
    pub recipe_markdown: &'static str,
    /// Discovered valid usage in the same repository, if available.
    pub exemplar: Option<SourceExcerpt>,
    /// Invariants that must be preserved when applying the transformation.
    pub invariants: Vec<&'static str>,
}

/// Clustered group of related diagnostics sharing a single underlying defect (see `GLOSSARY.md`: **Root-Cause Group**).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCauseGroup {
    /// Deterministic **Root-Cause Group** identifier (`rcg::...`).
    pub id: String,
    /// Primary rule identifier.
    pub rule: RuleId,
    /// Rule category.
    pub category: RuleCategory,
    /// Highest severity among clustered diagnostics.
    pub severity: RuleSeverity,
    /// **Prescription Tier** for the group.
    pub tier: PrescriptionTier,
    /// Primary file path of the root cause.
    pub file: PathBuf,
    /// Enclosing **Subject** name, if any.
    pub subject_name: Option<String>,
    /// Primary target name (prop, state slot, context, or component).
    pub target_name: String,
    /// Primary 1-based location.
    pub loc: SourceLoc,
    /// Summary message for the group.
    pub message: String,
    /// Static **Blast Radius** score and priority tier (`P0`–`P3`).
    pub blast_radius: BlastRadius,
    /// Indices into `JsonReport::diagnostics` belonging to this group.
    pub diagnostic_indices: Vec<usize>,
}

/// A single diagnostic emitted by `dotore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// File path where the diagnostic occurred.
    pub file: PathBuf,
    /// Enclosing **Subject** name (`"Form"`, `"useOnlineStatus"`, or `None` if anonymous/module-level).
    pub subject_name: Option<String>,
    /// Rule identifier.
    pub rule: RuleId,
    /// Rule category (`Bugs`, `Performance`, `Accessibility`, `Security`, `Maintainability`).
    pub category: RuleCategory,
    /// Effective severity (`Error` or `Warning`).
    pub severity: RuleSeverity,
    /// Message identifier (for compatibility with rule tests).
    pub message_id: &'static str,
    /// Prescription tier (`Autofix`, `Surgical`, `Refactor`).
    pub tier: PrescriptionTier,
    /// Primary target name (state name, prop name, component name, or data source).
    pub target_name: String,
    /// Human-readable diagnostic message.
    pub message: String,
    /// Official documentation link.
    pub docs_url: &'static str,
    /// 1-based line and column.
    pub loc: SourceLoc,
    /// Byte span of the flagged AST node.
    pub span: ByteSpan,
    /// Steps of the **Render Cascade** eliminated by fixing this diagnostic.
    pub cascade_steps: Vec<String>,
    /// Cross-file JSX **Caller Sites** relevant to this diagnostic (e.g. missing `key`).
    pub caller_sites: Vec<ResolvedCallerSite>,
    /// Optional deterministic auto-fix patch.
    pub autofix: Option<AutofixPatch>,
}

impl Diagnostic {
    /// Creates a [`Diagnostic`] for `rule`, automatically populating `category`, `severity`,
    /// `tier`, and `docs_url` from [`RuleId::metadata`].
    #[must_use]
    pub fn new(
        rule: RuleId,
        file: impl Into<PathBuf>,
        loc: SourceLoc,
        span: ByteSpan,
        target_name: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let meta = rule.metadata();
        Self {
            file: file.into(),
            subject_name: None,
            rule,
            category: meta.category,
            severity: meta.default_severity,
            message_id: "",
            tier: meta.default_tier,
            target_name: target_name.into(),
            message: message.into(),
            docs_url: meta.docs_url,
            loc,
            span,
            cascade_steps: Vec::new(),
            caller_sites: Vec::new(),
            autofix: None,
        }
    }

    /// Alias for [`Diagnostic::new`] starting a fluent diagnostic builder.
    #[must_use]
    pub fn builder(
        rule: RuleId,
        file: impl Into<PathBuf>,
        loc: SourceLoc,
        span: ByteSpan,
        target_name: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(rule, file, loc, span, target_name, message)
    }

    /// Creates a [`Diagnostic`] for `rule` with `target_name` defaulted to `rule.as_str()`.
    #[must_use]
    pub fn for_rule(
        rule: RuleId,
        file: impl Into<PathBuf>,
        loc: SourceLoc,
        span: ByteSpan,
        message: impl Into<String>,
    ) -> Self {
        Self::new(rule, file, loc, span, rule.as_str(), message)
    }

    /// Sets the optional enclosing **Subject** name (`Some(...)` or `None`).
    #[must_use]
    pub fn with_subject(mut self, subject_name: Option<String>) -> Self {
        self.subject_name = subject_name;
        self
    }

    /// Sets the enclosing **Subject** name.
    #[must_use]
    pub fn with_subject_name(mut self, subject_name: impl Into<String>) -> Self {
        self.subject_name = Some(subject_name.into());
        self
    }

    /// Overrides the effective [`RuleSeverity`] (`Error` or `Warning`).
    #[must_use]
    pub const fn with_severity(mut self, severity: RuleSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Overrides the [`PrescriptionTier`] (`Autofix`, `Surgical`, or `Refactor`).
    #[must_use]
    pub const fn with_tier(mut self, tier: PrescriptionTier) -> Self {
        self.tier = tier;
        self
    }

    /// Overrides the [`RuleCategory`].
    #[must_use]
    pub const fn with_category(mut self, category: RuleCategory) -> Self {
        self.category = category;
        self
    }

    /// Sets the static `message_id` token.
    #[must_use]
    pub const fn with_message_id(mut self, message_id: &'static str) -> Self {
        self.message_id = message_id;
        self
    }

    /// Overrides the primary `target_name`.
    #[must_use]
    pub fn with_target_name(mut self, target_name: impl Into<String>) -> Self {
        self.target_name = target_name.into();
        self
    }

    /// Overrides the documentation URL.
    #[must_use]
    pub const fn with_docs_url(mut self, docs_url: &'static str) -> Self {
        self.docs_url = docs_url;
        self
    }

    /// Replaces the **Render Cascade** step list.
    #[must_use]
    pub fn with_cascade_steps(mut self, steps: Vec<String>) -> Self {
        self.cascade_steps = steps;
        self
    }

    /// Appends a single step to the **Render Cascade** step list.
    #[must_use]
    pub fn with_cascade_step(mut self, step: impl Into<String>) -> Self {
        self.cascade_steps.push(step.into());
        self
    }

    /// Replaces the resolved cross-file **Caller Sites** list.
    #[must_use]
    pub fn with_caller_sites(mut self, caller_sites: Vec<ResolvedCallerSite>) -> Self {
        self.caller_sites = caller_sites;
        self
    }

    /// Appends a single resolved cross-file **Caller Site**.
    #[must_use]
    pub fn with_caller_site(mut self, caller_site: ResolvedCallerSite) -> Self {
        self.caller_sites.push(caller_site);
        self
    }

    /// Sets the optional [`AutofixPatch`] (`Some(patch)` or `None`).
    /// When `autofix` is `Some(...)`, also sets `tier` to [`PrescriptionTier::Autofix`].
    #[must_use]
    pub fn with_autofix(mut self, autofix: Option<AutofixPatch>) -> Self {
        if autofix.is_some() {
            self.tier = PrescriptionTier::Autofix;
        }
        self.autofix = autofix;
        self
    }

    /// Attaches a deterministic [`AutofixPatch`] and promotes `tier` to [`PrescriptionTier::Autofix`].
    #[must_use]
    pub fn with_patch(mut self, patch: AutofixPatch) -> Self {
        self.tier = PrescriptionTier::Autofix;
        self.autofix = Some(patch);
        self
    }

    /// Computes the deterministic occurrence identity (`<file>::<line>:<col>::dotore/<rule>::<digest>`).
    #[must_use]
    pub fn id(&self) -> String {
        crate::diff::compute_diagnostic_id(self, None)
    }

    /// Computes the rename- and formatting-resilient fingerprint (`fp::<rule>::<digest>`) for this diagnostic.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        crate::diff::compute_structural_fingerprint(self)
    }

    /// Computes the normalized AST-token fingerprint (`fp::<rule>::<digest>`) using the file's source text when available.
    #[must_use]
    pub fn fingerprint_with_source(&self, source: Option<&str>) -> String {
        crate::diff::compute_diagnostic_fingerprint(self, source)
    }

    /// Computes the deterministic **Root-Cause Group** identifier (`rcg::...`) for this diagnostic.
    #[must_use]
    pub fn root_cause_group_id(&self) -> String {
        crate::planner::compute_root_cause_group_id(self)
    }
}

impl Serialize for Diagnostic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("Diagnostic", 18)?;
        state.serialize_field("id", &self.id())?;
        state.serialize_field("fingerprint", &self.fingerprint())?;
        state.serialize_field("root_cause_group_id", &self.root_cause_group_id())?;
        state.serialize_field("file", &self.file)?;
        state.serialize_field("subject_name", &self.subject_name)?;
        state.serialize_field("rule", &self.rule)?;
        state.serialize_field("category", &self.category)?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("message_id", &self.message_id)?;
        state.serialize_field("tier", &self.tier)?;
        state.serialize_field("target_name", &self.target_name)?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("docs_url", &self.docs_url)?;
        state.serialize_field("loc", &self.loc)?;
        state.serialize_field("span", &self.span)?;
        state.serialize_field("cascade_steps", &self.cascade_steps)?;
        state.serialize_field("caller_sites", &self.caller_sites)?;
        state.serialize_field("autofix", &self.autofix)?;
        state.end()
    }
}

const fn default_source_loc() -> SourceLoc {
    SourceLoc { line: 1, column: 1 }
}

impl<'de> Deserialize<'de> for Diagnostic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct DiagnosticDe {
            file: PathBuf,
            #[serde(default)]
            subject_name: Option<String>,
            rule: RuleId,
            #[serde(default)]
            category: Option<RuleCategory>,
            #[serde(default)]
            severity: Option<RuleSeverity>,
            #[serde(default)]
            tier: Option<PrescriptionTier>,
            #[serde(default)]
            target_name: String,
            #[serde(default)]
            message: String,
            #[serde(default = "default_source_loc")]
            loc: SourceLoc,
            #[serde(default)]
            span: ByteSpan,
            #[serde(default)]
            cascade_steps: Vec<String>,
            #[serde(default)]
            caller_sites: Vec<ResolvedCallerSite>,
            #[serde(default)]
            autofix: Option<AutofixPatch>,
        }
        let raw = DiagnosticDe::deserialize(deserializer)?;
        let meta = raw.rule.metadata();
        Ok(Self {
            file: raw.file,
            subject_name: raw.subject_name,
            rule: raw.rule,
            category: raw.category.unwrap_or(meta.category),
            severity: raw.severity.unwrap_or(meta.default_severity),
            message_id: "",
            tier: raw.tier.unwrap_or(meta.default_tier),
            target_name: raw.target_name,
            message: raw.message,
            docs_url: meta.docs_url,
            loc: raw.loc,
            span: raw.span,
            cascade_steps: raw.cascade_steps,
            caller_sites: raw.caller_sites,
            autofix: raw.autofix,
        })
    }
}

impl<'de> Deserialize<'de> for FixCapsule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct FixCapsuleDe {
            root_cause_group_id: String,
            rule: RuleId,
            tier: PrescriptionTier,
            blast_radius: BlastRadius,
            subject_excerpt: SourceExcerpt,
            #[serde(default)]
            caller_site_excerpts: Vec<SourceExcerpt>,
            #[serde(default)]
            exemplar: Option<SourceExcerpt>,
        }
        let raw = FixCapsuleDe::deserialize(deserializer)?;
        Ok(Self {
            root_cause_group_id: raw.root_cause_group_id,
            rule: raw.rule,
            tier: raw.tier,
            blast_radius: raw.blast_radius,
            subject_excerpt: raw.subject_excerpt,
            caller_site_excerpts: raw.caller_site_excerpts,
            recipe_markdown: raw.rule.metadata().recipe_markdown,
            exemplar: raw.exemplar,
            invariants: crate::planner::invariants_for_rule(raw.rule, raw.tier),
        })
    }
}
