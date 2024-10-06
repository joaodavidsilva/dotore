# Two-phase IR and three-tier prescriptions

We build a single React **Subject** intermediate representation (`SubjectIr`) per file in parallel and a cross-file JSX caller index (`ProjectGraph`) in Rust, rather than running independent ESLint-style AST visitors per rule. Diagnostics are classified into three **Prescription Tiers** (`Autofix`, `Surgical`, `Refactor`) so deterministic single-**Subject** rewrites execute natively in Rust (`dotore fix`) while cross-**Subject** state-model changes are handed to the companion agent skill with full graph context.
