# 12: Three.js, React Three Fiber (`r3f`), WebGL & WebGPU Rule Family + 60fps Frame-Loop Call Graph

**What to build:** Port all 186 Three.js, React Three Fiber (`r3f`), WebGL, and WebGPU rules into the Rust engine and extend `ProjectGraph` to trace cross-file helper calls originating inside 60fps `useFrame` and `requestAnimationFrame` loops.

**Blocked by:** 01: Prefactor Rule Registry, Capability Gate, Config Loader, and Single-Pass OXC Pipeline, 04: Module Graph, Dead Code, Circular Dependencies, and Duplicate JSX Subtrees

**Status:** resolved

- [x] All 186 `r3f` and `webgl` rules (covering GPU resource disposal for geometries, materials, textures, render targets, and postprocessing passes; `useFrame` allocations, `setState` in frame loops, and synchronous WebGL readbacks; instancing thresholds; renderer and texture `SRGBColorSpace` configuration; shadow bias, normalBias, and camera frustum bounds; `<Canvas frameloop>` settings; `useLoader`/`useGLTF`/`useTexture` caching; and WebGPU initialization and material APIs) are implemented in Rust and gated on Three.js/R3F/WebGL capabilities.
- [x] `ProjectGraph` traces the cross-file call graph starting from every `useFrame` and `requestAnimationFrame` callback to detect transitive per-frame allocations (`new Vector3()`, `new Color()`, `new Matrix4()`, fresh arrays/objects) and `setState` invocations inside imported helper functions, assigning maximum 60fps **Blast Radius** weight.
- [x] Integration tests port the valid and invalid fixtures across Three.js, R3F, WebGL, and WebGPU rules with zero false positives.
