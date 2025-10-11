# ProtoHack Roadmap

_Last updated: 2025-10-10_

This document captures the near-term milestones that grew out of the generics
substitution workstream and frames the broader compiler/runtime evolution.

## Horizon Overview

| Horizon | Timeframe | Focus |
| --- | --- | --- |
| Horizon 0 | In progress | Harden substitution pipeline + diagnostics |
| Horizon 1 | Next 4-6 weeks | Extend generics across module/interop boundaries |
| Horizon 2 | 1-2 quarters | Production-ready VM/runtime ergonomics |

## Horizon 0 — Stabilize Generics Foundations

- ✅ Substitution metadata threaded end-to-end (compiler → serializer → VM).
- ✅ Runtime specialization dispatch table with binding fingerprints.
- ✅ Diagnostic payloads (JSON-friendly, localized hints).
- 🔄 Test matrix expansion (concurrency, stress, fuzzing) — _in flight_.

**Exit criteria**
- No known crashes in substitution pipeline.
- Baseline regression suite covers generic call/extend permutations.
- Tooling surfaces structured codes/hints for all generic failures.

## Horizon 1 — Global Controls & Interop

1. **Global Binding Controls**
   - Serialize `GenericBindingMap` in module headers.
   - Enforce binding agreements on import/link.
   - CLI flag: `protohack-runner --inspect-generics`.
2. **Interop-Aware Generics**
   - ✅ ABI metadata (`ProtoNativeSignature` + `ProtoTypeBindingSet`).
   - ✅ VM validates native registration against generics contracts.
   - ✅ Host SDK helpers/macros for declaring binding expectations.
3. **`extend` for Generic Crafts**
   - Declarative syntax `extend craft Foo<T> with Trait<U>`.
   - Type-check against trait constraints; override resolution.
   - Serialize extension provenance for tooling.

**Exit criteria**
- Cross-module binding conflicts emit deterministic diagnostics.
- Native extensions cannot register incompatible specializations.
- Extension blocks compile & execute with full binding safety.

## Horizon 2 — Expression Typing & Tooling Depth

1. **Expression Typing & Flow Checks**
   - Annotate AST with inferred `ProtoTypeTag`.
   - Validate arguments against specialized signatures.
   - Branch-sensitive narrowing (type guards).
2. **Developer Experience**
   - Language server: hover, go-to-definition, quick fixes referencing generics.
   - Runtime inspector: `--dump-specializations`, `--trace-generics`.
   - Docs: troubleshooting guide & sample projects.
3. **Performance + Observability**
   - Specialization cache metrics & introspection.
   - Optional JIT enhancements guided by binding info.

**Exit criteria**
- Compiler rejects mismatched expressions at analyze time.
- IDE integrations surface generics context inline.
- VM exposes observability hooks without measurable perf regression.

## Cross-Cutting Concerns

- **Compatibility:** Introduce module-format versioning + feature flags.
- **Localization:** Diagnostic string tables + runtime locale selection.
- **Security:** Ensure metadata does not leak sensitive type names in logs.
- **Release Readiness:** Document migration paths for existing bytecode archives.

## Next Steps

- [x] Formalize module header schema changes and update serializer tests.
- [x] Prototype `extend` parser + AST to validate syntax with real code samples.
- [ ] Align with host SDK maintainers on native ABI surface updates.
- [ ] Draft localization strategy for diagnostic catalog.

Owners for each item will be captured in the weekly project tracker; this page
remains the single source of truth for major milestone definitions and exit
criteria.
