//! Integration tests for Ticket #12:
//! - All 186 Three.js, React Three Fiber (`r3f`), WebGL, and WebGPU rules registered and gated by `CapabilityGate`
//! - Cross-file 60fps `useFrame` and `requestAnimationFrame` call graph in `ProjectGraph` with `P0` / `FrameLoop60Fps` `BlastRadius`
//! - Valid and invalid fixtures across Three.js, R3F, WebGL, WebGPU, TSL, and GLSL shader rules with zero false positives

use std::path::{Path, PathBuf};

use dotore::{
    BlastRadiusTier, CapabilityGate, DotoreConfig, RenderFrequency, RuleId, RuleTag,
    analyze_project_sources, analyze_source_with_config, rule_registry,
};

fn r3f_gate() -> CapabilityGate {
    CapabilityGate::from_package_json_str(
        r#"{
            "name": "r3f-app",
            "private": true,
            "dependencies": {
                "react": "^19.0.0",
                "three": "^0.181.0",
                "@react-three/fiber": "^10.0.0",
                "@react-three/drei": "^10.0.0",
                "@react-three/postprocessing": "^3.0.0"
            }
        }"#,
    )
}

fn three_only_gate() -> CapabilityGate {
    CapabilityGate::from_package_json_str(
        r#"{
            "name": "three-app",
            "private": true,
            "dependencies": {
                "react": "^19.0.0",
                "three": "^0.181.0"
            }
        }"#,
    )
}

#[cfg(test)]
fn assert_rule_fires(rule_id_str: &str, code: &str, gate: &CapabilityGate) {
    let rule = RuleId::parse(rule_id_str)
        .unwrap_or_else(|| panic!("Rule {rule_id_str} should be registered"));
    let diags = analyze_source_with_config(
        Path::new("src/Scene.tsx"),
        code,
        &DotoreConfig::default(),
        gate,
        Some(&[rule]),
    );
    assert!(
        diags.iter().any(|d| d.rule == rule),
        "Expected rule `{rule_id_str}` ({rule:?}) to fire on:\n{code}\nGot diagnostics: {diags:#?}"
    );
}

#[cfg(test)]
fn assert_rule_clean(rule_id_str: &str, code: &str, gate: &CapabilityGate) {
    let rule = RuleId::parse(rule_id_str)
        .unwrap_or_else(|| panic!("Rule {rule_id_str} should be registered"));
    let diags = analyze_source_with_config(
        Path::new("src/Scene.tsx"),
        code,
        &DotoreConfig::default(),
        gate,
        Some(&[rule]),
    );
    let matching: Vec<_> = diags.into_iter().filter(|d| d.rule == rule).collect();
    assert!(
        matching.is_empty(),
        "Expected rule `{rule_id_str}` ({rule:?}) to produce 0 diagnostics on:\n{code}\nGot: {matching:#?}"
    );
}

#[test]
fn all_186_r3f_three_and_webgl_rules_are_registered_and_capability_gated() {
    let registry = rule_registry();
    let webgl_tagged: Vec<_> = registry
        .iter()
        .filter(|m| {
            m.tags.contains(&RuleTag::Webgl)
                || m.tags.contains(&RuleTag::Three)
                || m.tags.contains(&RuleTag::R3f)
        })
        .collect();
    assert!(
        webgl_tagged.len() >= 186,
        "Expected at least 186 Three.js/R3F/WebGL rules in registry, found {}",
        webgl_tagged.len()
    );

    // Every canonical ID and legacy alias must resolve via RuleId::parse
    for expected_key in [
        "r3f-no-new-in-use-frame",
        "r3f-no-clone-in-use-frame",
        "r3f-no-state-in-use-frame",
        "r3f-no-set-state-in-use-frame",
        "r3f-no-sync-readback-in-use-frame",
        "r3f-prefer-instanced-mesh",
        "r3f-prefer-use-loader",
        "r3f-no-unstable-args",
        "r3f-no-unstable-args-prop",
        "r3f-no-dispose-loader-cache",
        "r3f-no-imperative-dispose-on-declarative-child",
        "r3f-require-transparent-for-opacity",
        "r3f-valid-texture-color-space",
        "r3f-webgpu-require-async-init",
        "r3f-webgpu-no-legacy-material-api",
        "r3f-webgpu-no-legacy-effect-composer",
        "three-no-geometry-in-frame-loop",
        "three-no-new-in-animation-loop",
        "three-require-owned-geometry-cleanup",
        "three-require-geometry-dispose",
        "three-require-owned-material-cleanup",
        "three-require-material-dispose",
        "three-require-owned-texture-cleanup",
        "three-require-texture-dispose",
        "three-require-render-target-cleanup",
        "three-require-render-target-dispose",
        "three-require-postprocessing-cleanup",
        "three-valid-texture-color-space",
        "three-valid-shadow-map-size",
        "three-valid-perspective-camera",
        "three-valid-orthographic-camera",
        "three-webgpu-require-init-before-sync-operation",
        "three-webgpu-no-legacy-material-api",
        "three-shader-no-version-directive",
        "three-shader-require-position-on-all-paths",
        "webgl-no-sync-readback-in-animation-loop",
    ] {
        assert!(
            RuleId::parse(expected_key).is_some(),
            "Expected RuleId::parse({expected_key:?}) to succeed"
        );
    }

    // Verify CapabilityGate behavior:
    // 1. Plain React gate (no three, no r3f) blocks R3F and Three rules
    let plain_react_gate = CapabilityGate::default_react();
    assert!(!plain_react_gate.allows_rule(RuleId::R3fNoNewInUseFrame.metadata()));
    assert!(!plain_react_gate.allows_rule(RuleId::ThreeValidPerspectiveCamera.metadata()));

    // 2. Three-only gate allows Three rules (including three-require-owned-texture-cleanup) but not R3F rules
    let three_gate = three_only_gate();
    assert!(three_gate.allows_rule(RuleId::ThreeValidPerspectiveCamera.metadata()));
    assert!(three_gate.allows_rule(RuleId::ThreeRequireOwnedTextureCleanup.metadata()));
    assert!(!three_gate.allows_rule(RuleId::R3fNoNewInUseFrame.metadata()));

    // 3. R3F gate allows both R3F and Three rules, and disables `three-require-owned-texture-cleanup` in favor of `r3f-require-owned-texture-cleanup`
    let fiber_gate = r3f_gate();
    assert!(fiber_gate.allows_rule(RuleId::R3fNoNewInUseFrame.metadata()));
    assert!(fiber_gate.allows_rule(RuleId::R3fRequireOwnedTextureCleanup.metadata()));
    assert!(fiber_gate.allows_rule(RuleId::ThreeValidPerspectiveCamera.metadata()));
    assert!(!fiber_gate.allows_rule(RuleId::ThreeRequireOwnedTextureCleanup.metadata()));
}

#[test]
fn project_graph_traces_cross_file_60fps_use_frame_and_raf_helper_call_graph() {
    let files = vec![
        (
            PathBuf::from("package.json"),
            r#"{
                "name": "3d-game",
                "private": true,
                "dependencies": {
                    "react": "^19.0.0",
                    "three": "^0.181.0",
                    "@react-three/fiber": "^10.0.0"
                }
            }"#
            .to_string(),
        ),
        (
            PathBuf::from("src/math.ts"),
            r#"
            import { Vector3, Color, Matrix4 } from 'three';

            export function computeImpulse(dt: number, baseVec: Vector3) {
                const v = new Vector3(0, dt, 0);
                const c = new Color(0xff0000);
                const m = new Matrix4();
                const cloned = baseVec.clone();
                const scratchArr = [v, c, m, cloned];
                const scratchObj = { v, dt };
                return { scratchArr, scratchObj };
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/physics.ts"),
            r#"
            import { Vector3 } from 'three';
            import { computeImpulse } from './math';

            export function stepPhysics(dt: number, baseVec: Vector3) {
                return computeImpulse(dt, baseVec);
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/hud.ts"),
            r#"
            export function syncHudState(setFps: (n: number) => void, dt: number) {
                setFps(Math.round(1 / dt));
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/rafHelpers.ts"),
            r#"
            import { BoxGeometry, Vector3 } from 'three';

            export function rebuildParticleGeometry() {
                const geom = new BoxGeometry(1, 1, 1);
                const offset = new Vector3(1, 2, 3);
                return { geom, offset };
            }

            export function sampleFramebuffer(gl: WebGLRenderingContext, pixels: Uint8Array) {
                gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/cleanPhysics.ts"),
            r#"
            import { Vector3 } from 'three';

            const SCRATCH = new Vector3();

            export function stepClean(dt: number) {
                SCRATCH.set(0, dt, 0);
                return SCRATCH;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/Scene.tsx"),
            r#"
            import { useState, useEffect, useRef } from 'react';
            import { useFrame } from '@react-three/fiber';
            import { Vector3 } from 'three';
            import { stepPhysics } from './physics';
            import { syncHudState } from './hud';
            import { rebuildParticleGeometry, sampleFramebuffer } from './rafHelpers';

            const BASE_VEC = new Vector3(1, 0, 0);

            export function GameScene({ gl }: { gl: WebGLRenderingContext }) {
                const [fps, setFps] = useState(60);
                const pixelsRef = useRef(new Uint8Array(4));

                useFrame((_state, delta) => {
                    stepPhysics(delta, BASE_VEC);
                    syncHudState(setFps, delta);
                });

                useEffect(() => {
                    let id = 0;
                    function animate() {
                        id = requestAnimationFrame(animate);
                        rebuildParticleGeometry();
                        sampleFramebuffer(gl, pixelsRef.current);
                    }
                    id = requestAnimationFrame(animate);
                    return () => cancelAnimationFrame(id);
                }, [gl]);

                return <mesh name={String(fps)} />;
            }
            "#
            .to_string(),
        ),
        (
            PathBuf::from("src/CleanScene.tsx"),
            r#"
            import { useFrame } from '@react-three/fiber';
            import { stepClean } from './cleanPhysics';

            export function CleanScene() {
                useFrame((_state, delta) => {
                    stepClean(delta);
                });
                return <mesh />;
            }
            "#
            .to_string(),
        ),
    ];

    let report = analyze_project_sources(files, None);

    // CleanScene and cleanPhysics must have ZERO diagnostics
    let clean_diags: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|d| {
            d.file == Path::new("src/CleanScene.tsx") || d.file == Path::new("src/cleanPhysics.ts")
        })
        .collect();
    assert!(
        clean_diags.is_empty(),
        "Expected zero diagnostics on CleanScene/cleanPhysics, got: {clean_diags:#?}"
    );

    // Transitive `useFrame -> stepPhysics -> computeImpulse` allocations (`new Vector3`, `new Color`, `new Matrix4`, `.clone()`, fresh array/object)
    let use_frame_new_diags: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::R3fNoNewInUseFrame)
        .collect();
    assert!(
        !use_frame_new_diags.is_empty(),
        "Expected R3fNoNewInUseFrame from cross-file stepPhysics -> computeImpulse, got: {:#?}",
        report.diagnostics
    );
    assert!(
        use_frame_new_diags.iter().any(|d| {
            d.cascade_steps.iter().any(|s| s.contains("stepPhysics"))
                && d.cascade_steps.iter().any(|s| s.contains("computeImpulse"))
        }),
        "Expected cross-file call chain in cascade_steps, got: {use_frame_new_diags:#?}"
    );

    // Transitive `.clone()` inside `computeImpulse`
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::R3fNoCloneInUseFrame),
        "Expected R3fNoCloneInUseFrame from cross-file computeImpulse, got: {:#?}",
        report.diagnostics
    );

    // Transitive `setState` (`setFps`) inside `syncHudState`
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::R3fNoStateInUseFrame),
        "Expected R3fNoStateInUseFrame from cross-file syncHudState, got: {:#?}",
        report.diagnostics
    );

    // Transitive `requestAnimationFrame -> rebuildParticleGeometry` (`new BoxGeometry`, `new Vector3`)
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::ThreeNoGeometryInFrameLoop),
        "Expected ThreeNoGeometryInFrameLoop from cross-file rebuildParticleGeometry, got: {:#?}",
        report.diagnostics
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::ThreeNoNewInAnimationLoop),
        "Expected ThreeNoNewInAnimationLoop from cross-file rebuildParticleGeometry, got: {:#?}",
        report.diagnostics
    );

    // Transitive `requestAnimationFrame -> sampleFramebuffer` (`gl.readPixels`)
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::WebglNoSyncReadbackInAnimationLoop),
        "Expected WebglNoSyncReadbackInAnimationLoop from cross-file sampleFramebuffer, got: {:#?}",
        report.diagnostics
    );

    // Verify maximum 60fps BlastRadius weight (`FrameLoop60Fps` and `P0` tier)
    for rule in [
        RuleId::R3fNoNewInUseFrame,
        RuleId::R3fNoStateInUseFrame,
        RuleId::ThreeNoGeometryInFrameLoop,
        RuleId::WebglNoSyncReadbackInAnimationLoop,
    ] {
        let group = report
            .root_cause_groups
            .iter()
            .find(|g| g.rule == rule)
            .unwrap_or_else(|| panic!("Expected RootCauseGroup for {rule:?}"));
        assert_eq!(
            group.blast_radius.render_frequency,
            RenderFrequency::FrameLoop60Fps,
            "Expected FrameLoop60Fps for {rule:?}"
        );
        assert_eq!(
            group.blast_radius.tier,
            BlastRadiusTier::P0,
            "Expected P0 tier for 60fps rule {rule:?}"
        );
        assert!(group.blast_radius.score >= 100);
    }
}

#[test]
fn real_world_r3f_fixtures_and_frame_loop_rules_have_zero_false_positives() {
    let gate = r3f_gate();

    // 1. r3f-no-unstable-args
    assert_rule_clean(
        "r3f-no-unstable-args",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const Box = () => <boxGeometry args={[1, 1, 1]} />;
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-unstable-args",
        r#"
        import * as React from "react";
        import { Canvas } from "@react-three/fiber";
        import { Shape } from "three";
        export const RoundedBox = () => {
            const shape = React.useMemo(() => new Shape(), []);
            const params = React.useMemo(() => ({ depth: 1 }), []);
            return <extrudeGeometry args={[shape, params]} />;
        };
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-no-unstable-args",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const Grass = ({ offsets }) => <instancedBufferAttribute args={[new Float32Array(offsets), 3]} />;
        "#,
        &gate,
    );

    // 2. r3f-no-inline-primitive-object & r3f-no-inline-resource-prop
    assert_rule_fires(
        "r3f-no-inline-primitive-object",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const Suzanne = ({ nodes }) => <primitive object={nodes.Suzanne.clone()} />;
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-inline-primitive-object",
        r#"
        import { useMemo } from "react";
        import { Canvas } from "@react-three/fiber";
        export const Pixelation = () => {
            const effect = useMemo(() => createEffect(), []);
            return <primitive object={effect} />;
        };
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-no-inline-resource-prop",
        r#"
        import { Canvas } from "@react-three/fiber";
        import { BoxGeometry, MeshStandardMaterial } from "three";
        export const BadMesh = () => (
            <mesh geometry={new BoxGeometry(1, 1, 1)} material={new MeshStandardMaterial()} />
        );
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-inline-resource-prop",
        r#"
        import { useMemo } from "react";
        import { Canvas } from "@react-three/fiber";
        import { BoxGeometry } from "three";
        export const GoodMesh = () => {
            const geo = useMemo(() => new BoxGeometry(1, 1, 1), []);
            return <mesh geometry={geo} />;
        };
        "#,
        &gate,
    );

    // 3. r3f-no-state-in-use-frame (including guarded transitions allowed)
    assert_rule_fires(
        "r3f-no-state-in-use-frame",
        r#"
        import { useState } from "react";
        import { useFrame } from "@react-three/fiber";
        export const Targets = () => {
            const [targets, setTargets] = useState([]);
            useFrame(() => {
                if (targets.find((target) => target.hit)) {
                    setTargets(targets.filter((target) => !target.hit));
                }
            });
            return null;
        };
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-state-in-use-frame",
        r#"
        import { useState } from "react";
        import { useFrame } from "@react-three/fiber";
        export const Box = ({ width }) => {
            const [size, setSize] = useState([0, 0]);
            useFrame(() => {
                if (width !== size[0]) setSize([width, size[1]]);
            });
            return null;
        };
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-state-in-use-frame",
        r#"
        import { useState } from "react";
        import { useFrame } from "@react-three/fiber";
        export const Guarded = ({ callback }) => {
            const [error, setError] = useState(null);
            useFrame((state, delta) => {
                try {
                    callback(state, delta);
                } catch (caughtError) {
                    setError(caughtError);
                }
            });
            return error;
        };
        "#,
        &gate,
    );

    // 4. r3f-no-new-in-use-frame & r3f-no-clone-in-use-frame & r3f-require-frame-delta & r3f-no-advancing-clock-in-use-frame & r3f-no-async-use-frame
    assert_rule_fires(
        "r3f-no-new-in-use-frame",
        r#"
        import * as RAPIER from "@dimforge/rapier3d-compat";
        import { useFrame } from "@react-three/fiber";
        export const Player = ({ world, body }) => {
            useFrame(() => world.castRay(new RAPIER.Ray(body.translation(), { x: 0, y: -1, z: 0 })));
            return null;
        };
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-new-in-use-frame",
        r#"
        import { useFrame } from "@react-three/fiber";
        import { Vector3 } from "three";
        export const ConditionalInit = ({ ref }) => {
            useFrame(() => {
                if (!ref.current) {
                    ref.current = new Vector3();
                }
            });
            return null;
        };
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-no-clone-in-use-frame",
        r#"
        import { useRef } from "react";
        import { useFrame } from "@react-three/fiber";
        export const Billboard = () => {
            const inner = useRef();
            useFrame(() => {
                const previousRotation = inner.current.rotation.clone();
                consume(previousRotation);
            });
            return <group ref={inner} />;
        };
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-require-frame-delta",
        r#"
        import { useRef } from "react";
        import { useFrame } from "@react-three/fiber";
        export const Geo = () => {
            const group = useRef();
            useFrame(() => {
                group.current.rotation.z += 0.005;
            });
            return <group ref={group} />;
        };
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-require-frame-delta",
        r#"
        import { useRef } from "react";
        import { useFrame } from "@react-three/fiber";
        export const GeoDelta = () => {
            const group = useRef();
            useFrame((_, delta) => {
                group.current.rotation.z += 0.5 * delta;
            });
            return <group ref={group} />;
        };
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-no-advancing-clock-in-use-frame",
        r#"
        import { useFrame } from "@react-three/fiber";
        export const Geo = () => {
            useFrame(({ clock }) => consume(clock.getElapsedTime()));
            return null;
        };
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-advancing-clock-in-use-frame",
        r#"
        import { useFrame } from "@react-three/fiber";
        export const Geo = () => {
            useFrame(({ clock }) => consume(clock.elapsedTime));
            return null;
        };
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-no-async-use-frame",
        r#"
        import { useFrame } from "@react-three/fiber";
        export const Autofocus = ({ update }) => {
            useFrame(async (_, delta) => {
                update(delta);
            });
            return null;
        };
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-no-fresh-use-three-selector",
        r#"
        import { useThree } from "@react-three/fiber";
        export const Controls = () => {
            const [camera] = useThree((state) => [state.camera]);
            return camera;
        };
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-fresh-use-three-selector",
        r#"
        import { useThree } from "@react-three/fiber";
        export const Controls = () => {
            const camera = useThree((state) => state.camera);
            return camera;
        };
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-no-deep-use-three-selector",
        r#"
        import { useThree } from "@react-three/fiber";
        export const CameraFov = () => {
            const fov = useThree((state) => state.camera.fov);
            return fov;
        };
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-no-duplicate-primitive-object",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const DuplicatePrim = ({ model }) => (
            <>
                <primitive object={model} />
                <primitive object={model} />
            </>
        );
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-duplicate-primitive-object",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const Objects = ({ objects }) => (
            <>{objects.map((object) => <primitive key={object.uuid} object={object} />)}</>
        );
        "#,
        &gate,
    );
    assert_rule_fires(
        "r3f-no-internal-imports",
        r#"
        import { DomEvent } from "@react-three/fiber/dist/declarations/src/core/events";
        consume(DomEvent);
        "#,
        &gate,
    );
    assert_rule_clean(
        "r3f-no-internal-imports",
        r#"
        import { Canvas } from "@react-three/fiber";
        consume(Canvas);
        "#,
        &gate,
    );
}

#[test]
fn resource_disposal_and_loader_cache_rules_validate_ownership_and_cleanup() {
    let fiber_gate = r3f_gate();
    let three_gate = three_only_gate();

    // 1. three-require-owned-geometry-cleanup & three-require-owned-material-cleanup & three-require-owned-texture-cleanup
    assert_rule_fires(
        "three-require-owned-geometry-cleanup",
        r#"
        import { useEffect } from "react";
        import { BoxGeometry } from "three";
        export function LeakyMesh() {
            useEffect(() => {
                const geo = new BoxGeometry(1, 1, 1);
                geo.computeBoundingBox();
            }, []);
            return null;
        }
        "#,
        &three_gate,
    );
    assert_rule_clean(
        "three-require-owned-geometry-cleanup",
        r#"
        import { useEffect } from "react";
        import { BoxGeometry } from "three";
        export function CleanMesh() {
            useEffect(() => {
                const geo = new BoxGeometry(1, 1, 1);
                return () => geo.dispose();
            }, []);
            return null;
        }
        "#,
        &three_gate,
    );

    assert_rule_fires(
        "three-require-owned-material-cleanup",
        r#"
        import { useEffect } from "react";
        import { MeshStandardMaterial } from "three";
        export function LeakyMaterial() {
            useEffect(() => {
                const mat = new MeshStandardMaterial({ color: 0xff0000 });
                mat.needsUpdate = true;
            }, []);
            return null;
        }
        "#,
        &three_gate,
    );
    assert_rule_clean(
        "three-require-owned-material-cleanup",
        r#"
        import { useEffect } from "react";
        import { MeshStandardMaterial } from "three";
        export function CleanMaterial() {
            useEffect(() => {
                const mat = new MeshStandardMaterial({ color: 0xff0000 });
                return () => mat.dispose();
            }, []);
            return null;
        }
        "#,
        &three_gate,
    );

    assert_rule_fires(
        "three-require-owned-texture-cleanup",
        r#"
        import { useEffect } from "react";
        import { DataTexture } from "three";
        export function LeakyTexture() {
            useEffect(() => {
                const tex = new DataTexture(new Uint8Array(4), 1, 1);
                tex.needsUpdate = true;
            }, []);
            return null;
        }
        "#,
        &three_gate,
    );
    assert_rule_clean(
        "three-require-owned-texture-cleanup",
        r#"
        import { useEffect } from "react";
        import { DataTexture } from "three";
        export function CleanTexture() {
            useEffect(() => {
                const tex = new DataTexture(new Uint8Array(4), 1, 1);
                return () => tex.dispose();
            }, []);
            return null;
        }
        "#,
        &three_gate,
    );

    // 2. three-require-render-target-cleanup & three-require-postprocessing-cleanup & three-require-renderer-cleanup
    assert_rule_fires(
        "three-require-render-target-cleanup",
        r#"
        import { useEffect } from "react";
        import { WebGLRenderTarget } from "three";
        export function LeakyRT() {
            useEffect(() => {
                const rt = new WebGLRenderTarget(256, 256);
                console.log(rt.width);
            }, []);
            return null;
        }
        "#,
        &three_gate,
    );
    assert_rule_clean(
        "three-require-render-target-cleanup",
        r#"
        import { useEffect } from "react";
        import { WebGLRenderTarget } from "three";
        export function CleanRT() {
            useEffect(() => {
                const rt = new WebGLRenderTarget(256, 256);
                return () => rt.dispose();
            }, []);
            return null;
        }
        "#,
        &three_gate,
    );

    assert_rule_fires(
        "three-require-postprocessing-cleanup",
        r#"
        import { useEffect } from "react";
        import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
        export function LeakyPost({ renderer }) {
            useEffect(() => {
                const composer = new EffectComposer(renderer);
                composer.render();
            }, [renderer]);
            return null;
        }
        "#,
        &three_gate,
    );
    assert_rule_clean(
        "three-require-postprocessing-cleanup",
        r#"
        import { useEffect } from "react";
        import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
        export function CleanPost({ renderer }) {
            useEffect(() => {
                const composer = new EffectComposer(renderer);
                composer.render();
                return () => composer.dispose();
            }, [renderer]);
            return null;
        }
        "#,
        &three_gate,
    );

    // 3. r3f-no-dispose-loader-cache & r3f-no-mutate-loader-cache & r3f-prefer-use-loader & r3f-no-null-loader-input
    assert_rule_fires(
        "r3f-no-dispose-loader-cache",
        r#"
        import { useEffect } from "react";
        import { useGLTF } from "@react-three/drei";
        export function Model() {
            const { nodes } = useGLTF("/robot.glb");
            useEffect(() => () => {
                nodes.arm.geometry.dispose();
            }, [nodes]);
            return <primitive object={nodes.arm} />;
        }
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-no-mutate-loader-cache",
        r#"
        import { useGLTF } from "@react-three/drei";
        export function Model() {
            const { scene } = useGLTF("/robot.glb");
            scene.position.set(1, 2, 3);
            return <primitive object={scene} />;
        }
        "#,
        &fiber_gate,
    );
    assert_rule_clean(
        "r3f-no-mutate-loader-cache",
        r#"
        import { useMemo } from "react";
        import { useGLTF } from "@react-three/drei";
        export function Model() {
            const { scene } = useGLTF("/robot.glb");
            const copy = useMemo(() => scene.clone(), [scene]);
            copy.position.set(1, 2, 3);
            return <primitive object={copy} />;
        }
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-prefer-use-loader",
        r#"
        import { useEffect } from "react";
        import { useThree } from "@react-three/fiber";
        import { TextureLoader } from "three";
        export function BadLoader() {
            useThree();
            useEffect(() => {
                new TextureLoader().load("/tex.png", () => {});
            }, []);
            return <mesh />;
        }
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-no-null-loader-input",
        r#"
        import { useTexture } from "@react-three/drei";
        export function NullableTex({ url }: { url?: string }) {
            const tex = useTexture(url ? url : null);
            return <meshBasicMaterial map={tex} />;
        }
        "#,
        &fiber_gate,
    );
}

#[test]
fn instancing_color_space_cameras_shadows_materials_and_buffers_rules() {
    let fiber_gate = r3f_gate();
    let three_gate = three_only_gate();

    // 1. r3f-prefer-instanced-mesh & three-prefer-instanced-mesh
    assert_rule_fires(
        "r3f-prefer-instanced-mesh",
        r#"
        import { Canvas } from "@react-three/fiber";
        import { BoxGeometry, MeshStandardMaterial } from "three";
        const sharedGeo = new BoxGeometry(1, 1, 1);
        const sharedMat = new MeshStandardMaterial();
        const POSITIONS = [[0, 0, 0], [1, 0, 0], [2, 0, 0]];
        export function Crowd() {
            return (
                <group>
                    {POSITIONS.map((pos, idx) => (
                        <mesh key={idx} geometry={sharedGeo} material={sharedMat} position={pos} />
                    ))}
                </group>
            );
        }
        "#,
        &fiber_gate,
    );

    // 2. r3f-valid-texture-color-space & three-valid-texture-color-space
    assert_rule_fires(
        "r3f-valid-texture-color-space",
        r#"
        import { Canvas } from "@react-three/fiber";
        import { NoColorSpace, SRGBColorSpace } from "three";
        export function BadColorSpace({ albedo, normal }) {
            albedo.colorSpace = NoColorSpace;
            normal.colorSpace = SRGBColorSpace;
            return <meshStandardMaterial map={albedo} normalMap={normal} />;
        }
        "#,
        &fiber_gate,
    );
    assert_rule_clean(
        "r3f-valid-texture-color-space",
        r#"
        import { Canvas } from "@react-three/fiber";
        import { NoColorSpace, SRGBColorSpace } from "three";
        export function GoodColorSpace({ albedo, normal }) {
            albedo.colorSpace = SRGBColorSpace;
            normal.colorSpace = NoColorSpace;
            return <meshStandardMaterial map={albedo} normalMap={normal} />;
        }
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "three-valid-texture-color-space",
        r#"
        import { MeshStandardMaterial, NoColorSpace, Texture } from "three";
        const tex = new Texture();
        tex.colorSpace = NoColorSpace;
        export const mat = new MeshStandardMaterial({ map: tex });
        "#,
        &three_gate,
    );

    // 3. Camera frustum bounds (`r3f-valid-perspective-camera`, `three-valid-perspective-camera`, `r3f-valid-orthographic-camera`, `three-valid-orthographic-camera`)
    assert_rule_fires(
        "r3f-valid-perspective-camera",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const BadCam = () => <perspectiveCamera args={[75, 1.5, 0, 100]} />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "three-valid-perspective-camera",
        r#"
        import { PerspectiveCamera } from "three";
        export const cam = new PerspectiveCamera(75, 1.5, 100, 10);
        "#,
        &three_gate,
    );
    assert_rule_clean(
        "three-valid-perspective-camera",
        r#"
        import { PerspectiveCamera } from "three";
        export const cam = new PerspectiveCamera(75, 1.5, 0.1, 1000);
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "r3f-valid-orthographic-camera",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const BadOrtho = () => <orthographicCamera left={-10} right={-10} top={10} bottom={-10} near={0.1} far={100} />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "three-valid-orthographic-camera",
        r#"
        import { OrthographicCamera } from "three";
        export const cam = new OrthographicCamera(-10, 10, 10, -10, 100, 10);
        "#,
        &three_gate,
    );

    // 4. Shadows (`r3f-valid-shadow-map-size`, `three-valid-shadow-map-size`, `r3f-no-shadows-on-unsupported-light`, `r3f-require-shadows-enabled`, `r3f-limit-shadowed-point-lights`)
    assert_rule_fires(
        "r3f-valid-shadow-map-size",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const BadShadow = () => <directionalLight castShadow shadow-mapSize={[1000, 1024]} />;
        "#,
        &fiber_gate,
    );
    assert_rule_clean(
        "r3f-valid-shadow-map-size",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const GoodShadow = () => <directionalLight castShadow shadow-mapSize={[1024, 1024]} />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "three-valid-shadow-map-size",
        r#"
        import { DirectionalLight } from "three";
        const light = new DirectionalLight();
        light.shadow.mapSize.set(500, 512);
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "r3f-no-shadows-on-unsupported-light",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const BadAmbient = () => <ambientLight castShadow />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-require-shadows-enabled",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const MissingShadowsProp = () => (
            <Canvas>
                <directionalLight castShadow />
                <mesh castShadow receiveShadow />
            </Canvas>
        );
        "#,
        &fiber_gate,
    );
    assert_rule_clean(
        "r3f-require-shadows-enabled",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const WithShadowsProp = () => (
            <Canvas shadows>
                <directionalLight castShadow />
                <mesh castShadow receiveShadow />
            </Canvas>
        );
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-limit-shadowed-point-lights",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const TooManyPointShadows = () => (
            <group>
                <pointLight castShadow />
                <pointLight castShadow />
                <pointLight castShadow />
            </group>
        );
        "#,
        &fiber_gate,
    );

    // 5. Materials, opacity, PBR, buffers
    assert_rule_fires(
        "r3f-require-transparent-for-opacity",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const IgnoredOpacity = () => <meshStandardMaterial opacity={0.5} />;
        "#,
        &fiber_gate,
    );
    assert_rule_clean(
        "r3f-require-transparent-for-opacity",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const ValidOpacity = () => <meshStandardMaterial opacity={0.5} transparent />;
        "#,
        &fiber_gate,
    );
    assert_rule_clean(
        "r3f-require-transparent-for-opacity",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const DefaultTransparentSprite = () => <spriteMaterial opacity={0.5} />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-valid-material-opacity",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const OutOfRangeOpacity = () => <meshBasicMaterial opacity={1.5} transparent />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-valid-pbr-material-properties",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const OutOfRangePbr = () => <meshStandardMaterial roughness={1.5} metalness={-0.2} />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-valid-physical-material-properties",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const BadIor = () => <meshPhysicalMaterial ior={0.5} clearcoat={2} />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-valid-buffer-attribute-array-length",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const BadBuffer = () => <bufferAttribute args={[new Float32Array(5), 3]} />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-valid-buffer-attribute-item-size",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const BadItemSize = () => <bufferAttribute args={[new Float32Array(6), 0]} />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-texture-repeat-requires-wrapping",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const BadRepeat = () => <texture repeat={[4, 4]} />;
        "#,
        &fiber_gate,
    );
}

#[test]
fn webgpu_tsl_and_glsl_shader_rules_validate_async_init_legacy_apis_and_shaders() {
    let fiber_gate = r3f_gate();
    let three_gate = three_only_gate();

    // 1. WebGPU rules
    assert_rule_fires(
        "r3f-webgpu-require-async-init",
        r#"
        import { Canvas } from "@react-three/fiber";
        import { WebGPURenderer } from "three/webgpu";
        export const BadWebgpuCanvas = () => (
            <Canvas gl={(canvas) => new WebGPURenderer({ canvas })} />
        );
        "#,
        &fiber_gate,
    );
    assert_rule_clean(
        "r3f-webgpu-require-async-init",
        r#"
        import { Canvas } from "@react-three/fiber";
        import { WebGPURenderer } from "three/webgpu";
        export const GoodWebgpuCanvas = () => (
            <Canvas
                gl={async (props) => {
                    const renderer = new WebGPURenderer(props);
                    await renderer.init();
                    return renderer;
                }}
            />
        );
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-webgpu-canvas-prop-compatibility",
        r#"
        import { Canvas } from "@react-three/fiber/webgpu";
        export const BadWebgpuProp = () => <Canvas gl={{ antialias: true }} />;
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-webgpu-no-gl-state",
        r#"
        import { useThree } from "@react-three/fiber/webgpu";
        export const BadGlState = () => {
            const { gl } = useThree();
            return gl;
        };
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-webgpu-no-legacy-material-api",
        r#"
        import { Canvas } from "@react-three/fiber/webgpu";
        export const BadLegacyShader = () => (
            <Canvas>
                <mesh>
                    <shaderMaterial vertexShader="void main() {}" fragmentShader="void main() {}" />
                </mesh>
            </Canvas>
        );
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-webgpu-no-legacy-effect-composer",
        r#"
        import { Canvas } from "@react-three/fiber/webgpu";
        import { EffectComposer } from "@react-three/postprocessing";
        export const BadComposer = () => (
            <Canvas>
                <EffectComposer children={null} />
            </Canvas>
        );
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "three-webgpu-require-init-before-sync-operation",
        r#"
        import { WebGPURenderer } from "three/webgpu";
        export function renderWithoutInit(scene, camera) {
            const renderer = new WebGPURenderer();
            renderer.render(scene, camera);
        }
        "#,
        &three_gate,
    );
    assert_rule_clean(
        "three-webgpu-require-init-before-sync-operation",
        r#"
        import { WebGPURenderer } from "three/webgpu";
        export async function renderAfterInit(scene, camera) {
            const renderer = new WebGPURenderer();
            await renderer.init();
            renderer.render(scene, camera);
        }
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-webgpu-no-legacy-material-api",
        r#"
        import { WebGPURenderer, ShaderMaterial } from "three/webgpu";
        const renderer = new WebGPURenderer();
        const mat = new ShaderMaterial({});
        console.log(renderer, mat);
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-tsl-no-js-uniform-branch",
        r#"
        import { Fn, uniform } from "three/tsl";
        const uToggle = uniform(1);
        export const shaderFn = Fn(() => {
            if (uToggle.value > 0.5) {
                return 1;
            }
            return 0;
        });
        "#,
        &three_gate,
    );

    // 2. GLSL Shader rules (`three-shader-*` and `three-raw-shader-*`)
    assert_rule_fires(
        "three-shader-no-version-directive",
        r##"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            vertexShader: "#version 300 es\nvoid main() { gl_Position = vec4(0.0); }",
        });
        "##,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-reserved-identifiers",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "uniform float gl_customVal;\nvoid main() { gl_FragColor = vec4(gl_customVal); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-redeclared-builtins",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            vertexShader: "attribute vec3 position;\nvoid main() { gl_Position = vec4(position, 1.0); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-invalid-clamp-bounds",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "void main() { float x = clamp(0.5, 1.0, 0.0); gl_FragColor = vec4(x); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-invalid-smoothstep-edges",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "void main() { float x = smoothstep(1.0, 0.0, 0.5); gl_FragColor = vec4(x); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-prefer-small-integer-pow",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "void main() { float x = pow(0.5, 2.0); gl_FragColor = vec4(x); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-prefer-squared-distance-comparison",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "void main() { if (distance(vec2(0.0), vec2(1.0)) < 2.0) { gl_FragColor = vec4(1.0); } }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-require-position-on-all-paths",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            vertexShader: "uniform bool uSkip;\nvoid main() { if (uSkip) return; gl_Position = vec4(0.0); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_clean(
        "three-shader-require-position-on-all-paths",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            vertexShader: "void main() { gl_Position = vec4(0.0, 0.0, 0.0, 1.0); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-require-fragment-output-on-all-paths",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "uniform bool uSkip;\nvoid main() { if (uSkip) return; gl_FragColor = vec4(1.0); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-raw-shader-require-fragment-float-precision",
        r#"
        import { RawShaderMaterial } from "three";
        export const mat = new RawShaderMaterial({
            fragmentShader: "void main() { float x = 1.0; gl_FragColor = vec4(x); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_clean(
        "three-raw-shader-require-fragment-float-precision",
        r#"
        import { RawShaderMaterial } from "three";
        export const mat = new RawShaderMaterial({
            fragmentShader: "precision mediump float;\nvoid main() { float x = 1.0; gl_FragColor = vec4(x); }",
        });
        "#,
        &three_gate,
    );
}

#[test]
fn scene_lighting_environment_geometry_attributes_and_glsl_uniform_interface_rules() {
    let fiber_gate = r3f_gate();
    let three_gate = three_only_gate();

    // 1. Closed-scene PBR lighting & metal environment (`r3f-require-lighting-for-pbr`, `r3f-require-environment-for-metal`, `three-require-lighting-for-pbr`, `three-require-environment-for-metal`)
    assert_rule_fires(
        "r3f-require-lighting-for-pbr",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const DarkScene = () => (
            <Canvas>
                <mesh>
                    <boxGeometry />
                    <meshStandardMaterial />
                </mesh>
            </Canvas>
        );
        "#,
        &fiber_gate,
    );
    assert_rule_clean(
        "r3f-require-lighting-for-pbr",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const LitScene = () => (
            <Canvas>
                <ambientLight intensity={0.5} />
                <mesh>
                    <boxGeometry />
                    <meshStandardMaterial />
                </mesh>
            </Canvas>
        );
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-require-environment-for-metal",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const UnreflectedMetal = () => (
            <Canvas>
                <directionalLight intensity={1} />
                <mesh>
                    <sphereGeometry />
                    <meshStandardMaterial metalness={1} roughness={0.1} />
                </mesh>
            </Canvas>
        );
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "three-require-lighting-for-pbr",
        r#"
        import { Scene, Mesh, BoxGeometry, MeshStandardMaterial, WebGLRenderer, PerspectiveCamera } from "three";
        const scene = new Scene();
        const camera = new PerspectiveCamera(75, 1, 0.1, 100);
        const renderer = new WebGLRenderer({ canvas });
        scene.add(new Mesh(new BoxGeometry(), new MeshStandardMaterial()));
        renderer.render(scene, camera);
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-require-environment-for-metal",
        r#"
        import { Scene, Mesh, SphereGeometry, MeshStandardMaterial, DirectionalLight, WebGLRenderer, PerspectiveCamera } from "three";
        const scene = new Scene();
        const camera = new PerspectiveCamera(75, 1, 0.1, 100);
        const renderer = new WebGLRenderer({ canvas });
        scene.add(new DirectionalLight());
        scene.add(new Mesh(new SphereGeometry(), new MeshStandardMaterial({ metalness: 1 })));
        renderer.render(scene, camera);
        "#,
        &three_gate,
    );

    // 2. Custom BufferGeometry normals & UVs (`r3f-require-lit-material-normals`, `r3f-require-uv-for-texture-map`, `three-require-lit-material-normals`, `three-require-uv-for-texture-map`)
    assert_rule_fires(
        "r3f-require-lit-material-normals",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const MissingNormals = ({ positions, normalTex }) => (
            <mesh>
                <bufferGeometry>
                    <bufferAttribute attach="attributes-position" args={[positions, 3]} />
                </bufferGeometry>
                <meshStandardMaterial normalMap={normalTex} />
            </mesh>
        );
        "#,
        &fiber_gate,
    );
    assert_rule_fires(
        "r3f-require-uv-for-texture-map",
        r#"
        import { Canvas } from "@react-three/fiber";
        export const MissingUvs = ({ positions, colorTex }) => (
            <mesh>
                <bufferGeometry>
                    <bufferAttribute attach="attributes-position" args={[positions, 3]} />
                </bufferGeometry>
                <meshStandardMaterial map={colorTex} />
            </mesh>
        );
        "#,
        &fiber_gate,
    );

    // 3. Renderer DOM attachment, size, resize, and EffectComposer (`three-require-renderer-dom-attachment`, `three-require-renderer-size`, `three-require-camera-aspect-on-resize`, `three-effect-composer-output-pass-last`, `three-effect-composer-require-size-on-resize`)
    assert_rule_fires(
        "three-require-renderer-dom-attachment",
        r#"
        import { WebGLRenderer, Scene, PerspectiveCamera } from "three";
        const renderer = new WebGLRenderer();
        renderer.setSize(800, 600);
        renderer.render(new Scene(), new PerspectiveCamera(75, 1.33, 0.1, 100));
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-require-renderer-size",
        r#"
        import { WebGLRenderer, Scene, PerspectiveCamera } from "three";
        const renderer = new WebGLRenderer();
        document.body.appendChild(renderer.domElement);
        renderer.render(new Scene(), new PerspectiveCamera(75, 1.33, 0.1, 100));
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-require-camera-aspect-on-resize",
        r#"
        import { WebGLRenderer, PerspectiveCamera } from "three";
        const renderer = new WebGLRenderer({ canvas });
        const camera = new PerspectiveCamera(75, 1, 0.1, 100);
        window.addEventListener("resize", () => {
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-effect-composer-output-pass-last",
        r#"
        import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
        import { OutputPass } from "three/addons/postprocessing/OutputPass.js";
        import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";
        const composer = new EffectComposer(renderer);
        composer.addPass(new OutputPass());
        composer.addPass(new UnrealBloomPass());
        "#,
        &three_gate,
    );

    // 4. GLSL uniform & stage interface rules (`three-shader-valid-uniform-definitions`, `three-shader-require-uniform-bindings`, `three-shader-require-compatible-uniform-values`, `three-shader-require-matching-uniforms`, `three-shader-require-matching-varyings`, `three-shader-valid-global-initializers`, `three-shader-no-inverse-of-uniform`, `three-shader-no-redundant-frag-depth`, `three-shader-no-derivatives-in-nonuniform-flow`, `three-shader-no-invalid-constant-math`, `three-shader-no-invalid-constant-bit-operations`, `three-shader-no-constant-out-of-bounds-index`)
    assert_rule_fires(
        "three-shader-valid-uniform-definitions",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            uniforms: { uTime: 1.0 },
            fragmentShader: "uniform float uTime;\nvoid main() { gl_FragColor = vec4(uTime); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-require-uniform-bindings",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            uniforms: {},
            fragmentShader: "uniform float uMissing;\nvoid main() { gl_FragColor = vec4(uMissing); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-require-compatible-uniform-values",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            uniforms: { uTime: { value: "invalid" } },
            fragmentShader: "uniform float uTime;\nvoid main() { gl_FragColor = vec4(uTime); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-require-matching-uniforms",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            uniforms: { uVal: { value: 1.0 } },
            vertexShader: "uniform float uVal;\nvoid main() { gl_Position = vec4(uVal); }",
            fragmentShader: "uniform vec3 uVal;\nvoid main() { gl_FragColor = vec4(uVal, 1.0); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-require-matching-varyings",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            vertexShader: "varying vec2 vUv;\nvoid main() { vUv = uv; gl_Position = vec4(position, 1.0); }",
            fragmentShader: "varying vec3 vColor;\nvoid main() { gl_FragColor = vec4(vColor, 1.0); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-valid-global-initializers",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "uniform float uTime = 1.0;\nvoid main() { gl_FragColor = vec4(uTime); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-inverse-of-uniform",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            uniforms: { uMat: { value: null } },
            vertexShader: "uniform mat4 uMat;\nvoid main() { gl_Position = inverse(uMat) * vec4(position, 1.0); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-redundant-frag-depth",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "void main() { gl_FragDepth = gl_FragCoord.z; gl_FragColor = vec4(1.0); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-derivatives-in-nonuniform-flow",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "varying float vMask;\nvoid main() { if (vMask > 0.5) { float d = dFdx(vMask); gl_FragColor = vec4(d); } }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-invalid-constant-math",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "void main() { float x = sqrt(-1.0); gl_FragColor = vec4(x); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-invalid-constant-bit-operations",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "void main() { int x = 1 << 32; gl_FragColor = vec4(float(x)); }",
        });
        "#,
        &three_gate,
    );
    assert_rule_fires(
        "three-shader-no-constant-out-of-bounds-index",
        r#"
        import { ShaderMaterial } from "three";
        export const mat = new ShaderMaterial({
            fragmentShader: "uniform vec3 uColor;\nvoid main() { float c = uColor[4]; gl_FragColor = vec4(c); }",
        });
        "#,
        &three_gate,
    );
}
