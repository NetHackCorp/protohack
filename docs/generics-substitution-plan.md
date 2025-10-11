# Protohack Generics — Type Substitution Plan

_Date: 2025-10-10_

This document captures the design for the first milestone toward fully-typed
generic crafts and methods.  The focus is the *substitution pipeline* that
translates syntactic type arguments into concrete runtime metadata and
compile-time validation.

## Goals

1. Provide a precise definition of the typing rules used when instantiating
   generic crafts, methods, and (eventually) `extend` declarations.
2. Describe the data structures required to represent type bindings during
   compilation.
3. Outline the algorithm used to verify explicit type arguments and to
   substitute them into parameter/return annotations and emitted metadata.
4. Prepare integration points in the compiler so subsequent milestones can
   plug in runtime dispatch and VM/JIT support.

## Terminology

- **Type parameter**: A symbolic placeholder introduced on a craft/class, e.g.
  `T` in `craft identity<T>(value as T) gives T`.
- **Type argument**: A concrete or symbolic instantiation provided at a call
  site, e.g. `num` in `identity<num>(42)`.
- **Binding**: The mapping from a type parameter slot to the concrete
  `ProtoTypeTag` chosen during specialization.

## Typing Rules

1. **Arity**
   - The number of type arguments at the call site must match the declared
     number of type parameters.  (Already enforced, reiterated here for
     completeness.)

2. **Argument domains**
   - Valid type argument tokens are the primitive type keywords (`num`,
     `text`, `flag`, `raw`, `pointer`, `none`) or identifiers that resolve to a
     currently in-scope type parameter.
   - The keyword `any` is *not* permitted as an explicit type argument; callers
     must omit the argument to default inference (future work) or select an
     actual type.

3. **Resolution of symbolic arguments**
   - When an identifier refers to an in-scope type parameter (e.g. calling
     `identity<U>` inside a craft parameterized by `U`), the callee must inherit
     the binding recorded on the caller.  If the caller is itself not yet
     specialized the binding remains symbolic and is carried forward.

4. **Substitution**
   - Each function parameter annotated with a type parameter index receives the
     corresponding concrete `ProtoTypeTag` once bindings are known.
   - The same substitution applies to the return type metadata.

5. **Verification**
   - When bindings are concrete, emitted bytecode must reflect the concrete
     `ProtoTypeTag`.  The compiler will also validate argument expressions
     against these tags once expression typing is available.
   - When bindings remain symbolic (e.g. re-exporting a generic without
     specifying arguments), metadata retains the symbolic form so downstream
     instantiations can continue the substitution chain.

## Data Structures

```c
typedef struct {
    ProtoTypeTag tag;        // concrete tag when resolved
    int8_t       param;      // -1 for concrete, otherwise index of symbolic param
    char         label[PROTOHACK_MAX_IDENTIFIER + 1];
} ProtoTypeBinding;

typedef struct {
    ProtoTypeBinding params[PROTOHACK_MAX_TYPE_PARAMS];
    uint8_t          count;
} ProtoTypeBindingSet;
```

- `ProtoTypeBinding` represents one slot (parameter or argument).  Either
  `tag` is concrete (`param == -1`) or it references a param index whose
  resolution is deferred.
- `ProtoTypeBindingSet` is stored on `ProtoFunction` specializations to capture
  both the final concrete arguments and any remaining symbolic ones.

Both structures will live under `include/protohack/function.h` once the code is
implemented.  Runtime consumers can then reason about generics uniformly.

## Compiler Algorithm

1. **Parse phase**
   - Extend `TemplateArg` to include `int8_t param_index`.  When parsing
     `<Identifier>` and the identifier resolves to an in-scope type parameter,
     store the index and mark the argument symbolic.

2. **Instantiation phase** (`ensure_function_specialization`)
   - Create a working `ProtoTypeBindingSet bindings` initialised from the
     template’s declared parameters.
   - For each parsed argument:
     - If concrete, set `bindings.params[i].tag` to the chosen tag.
     - If symbolic, look up the current binding for the referenced type
       parameter chain (function → enclosing function → class).  If found,
       copy the concrete tag; otherwise leave the binding symbolic and record
       `param_index`.
   - Apply the bindings to `instance->param_types`, `instance->return_type`,
     and `instance->type_arguments`.

3. **Verification phase**
   - If any binding remains symbolic after resolution while the template
     expects a concrete type (e.g. user supplied `any`), emit a compiler error.
   - Future milestone: walk call arguments (`compile_named_call`) and ensure
     the expression type is compatible with the substituted `ProtoTypeTag`.

4. **Metadata emission**
   - Persist the final `ProtoTypeBindingSet` inside the serialized function
     payload so tooling/VM can inspect both concrete and symbolic aspects.

## Integration Checklist

1. [x] Extend `TemplateArg` and parsing to capture symbolic references.
2. [x] Track caller bindings (`ProtoFunction::type_arguments`) within the
       `CompilerContext` stack.
3. [x] Modify `ensure_function_specialization` to build and apply
       `ProtoTypeBindingSet`.
4. [x] Surface substitution failures with actionable diagnostics.
5. [x] Update serializer/deserializer + debug description to include the new
  binding set.
6. [x] Add regression tests covering:
  - [x] Concrete instantiation.
  - [x] Nested generics passing symbolic arguments.
  - [x] Error conditions (missing bindings, arity mismatch, invalid tokens).

## Next Milestone — VM Specialization Dispatch

With substitution metadata flowing through compilation and serialization, the
next phase focuses on actually *using* those bindings at runtime.  The work
items below set up the VM so generic crafts can be invoked with concrete
instances.

### Objectives

1. Create a runtime lookup structure that maps `(function template, binding set)`
   pairs to concrete `ProtoFunction` specializations.
2. Extend bytecode call sites to carry enough information for the VM to select
   or lazily instantiate the correct specialization when executing `PROTO_OP_CALL`.
3. Introduce a mangling scheme (shared between compiler and VM) so serialized
   modules keep specialization identities stable across processes.
4. Record binding metadata inside VM frames so nested generic calls can inherit
   the caller’s symbolic substitutions.

### Proposed Steps

- **Runtime data model**
  - [x] Define specialization table storage on `ProtoVM` with helper APIs for
        registration, lookup, and clearing.
  - [x] Implement hashing/equals helpers for compact fingerprints if linear
    search proves insufficient.
- **Dispatch plumbing**
  - [x] Update `vm_call_value`/`call` helpers to consult the specialization table
        before invoking a craft obtained from bytecode.
  - [x] When a specialization is missing, allocate one by cloning the template and
        applying bindings (reusing compiler logic or sharing a helper in a common
        module).
- **Serialization coherence**
  - Reuse the mangled name generated in the compiler so deserialized functions
    can re-register their specializations without recomputing bindings.
- **Frame-level bindings**
  - [x] Store `ProtoTypeBindingSet` references on call frames and thread them into
        nested calls so symbolic arguments continue to resolve correctly at runtime.
- **Testing**
  - Add integration tests that exercise:
    - [x] Calling a specialized craft from plain bytecode.
    - [x] Nested calls where the callee inherits symbolic bindings from the caller.
    - [x] Serialization/deserialization followed by execution inside the VM.

Once these items are complete, we can iterate on expression typing and richer
error reporting with the assurance that runtime dispatch respects the binding
information produced during compilation.

## Next Milestone — Global Generic Controls

This phase extends the substitution pipeline from single-module scenarios to a
project-wide view, ensuring generic bindings remain coherent when crafts are
exported, imported, and composed across compilation units.

### Objectives

1. Embed generic binding metadata into serialized module headers so loaders can
   verify compatibility before linking.
2. Reject or warn on conflicting instantiations when two modules supply
   divergent bindings for the same generic export.
3. Provide scripting/tooling hooks so `protohack-runner` and IDE integrations
   can surface binding mismatches and suggest corrective actions.

### Guardrails & Data Flow

- **Metadata contract**: extend `ProtoExecutableHeader` with a `GenericBindingMap`
  that records, per export symbol, the required type parameters and any
  concrete bindings enforced by the producer module.
- **Import verification**: during `protohackc` link/load, compare the importing
  site’s requested bindings with the metadata captured in the header, raising a
  deterministic compiler error when they disagree.
- **Transitive aggregation**: accumulate binding constraints from dependencies
  so downstream modules inherit validated requirements without restating them.

### Work Breakdown

1. **Serialization**
   - [ ] Define `GenericBindingMap` structures in
         `include/protohack/serialize.h` and teach `serialize_module` /
         `deserialize_module` to persist them.
   - [ ] Add version gating so older modules without metadata trigger a
         downgrade path that assumes permissive bindings (with a warning).
2. **Compiler enforcement**
   - [ ] Update the import resolution step to request binding data from the
         deserializer and cross-check against the caller’s specialization.
   - [ ] Emit actionable diagnostics pointing to both producer and consumer
         source locations when conflicts arise.
3. **Tooling support**
   - [ ] Teach `protohack-runner` to print a concise table of export bindings
         when started with `--inspect-generics` for debugging.
   - [ ] Document the new inspector flag and add sample output to the README.
4. **Testing**
   - [ ] Integration test where module A exports `craft Box<T>` and module B
         imports `Box<num>` successfully, while module C requesting `Box<text>`
         fails with a clear error.
   - [ ] Regression test covering missing metadata paths to ensure fallback
         warnings fire but execution proceeds.

### Open Questions

- How should we version the metadata to remain compatible with existing
  bytecode archives? (Proposal: bump the module format and add a feature flag.)
- Should conflicting bindings be hard errors by default, or downgraded to
  warnings in watch-mode workflows? (Default to errors, allow opt-down via
  `--allow-generic-conflicts`.)
- What is the minimal surface we need to expose via IDE APIs so language
  servers can highlight binding issues inline?

## Next Milestone — Interop-Aware Generics

This milestone ensures specialized crafts retain type-safety guarantees when
crossing the boundary between ProtoHack code and native extensions (C stubs,
FFI hosts, or embedded runners).

### Objectives

1. Encode generic binding fingerprints into the native-call ABI so host code
   can validate arguments before invoking ProtoHack functions.
2. Allow native functions parameterized by ProtoHack generics to declare their
   expected bindings and have the VM enforce them during registration.
3. Provide tooling to introspect interop signatures, preventing accidental
   mismatches when mixing language runtimes.

### Interop Contract

- **ABI metadata**: extend `ProtoNativeSignature` with an optional
  `ProtoTypeBindingSet` reference describing concrete or symbolic expectations.
- **Call path enforcement**: when pushing a native frame, verify the caller’s
  binding set matches the native signature, emitting a runtime error otherwise.
- **Host shims**: update the generated stubs in `src/core/typed_memory.c` (or a
  new helper) so type tags are marshalled consistently for the host.

### Work Breakdown

1. **Compiler/Serializer**
   - [ ] Persist binding metadata for exported native stubs so the runtime can
     attach it during module load.
   - [ ] Ensure `protohackc` rejects attempts to register a native implementation
     whose declared bindings conflict with the specialized craft signature.
2. **Runtime Enforcement**
   - [ ] Extend VM native registration (`proto_native_register`) to store and
     validate binding sets.
   - [ ] Update VM call trampolines to pass the active binding set into native
     callbacks for inspection.
3. **Host API Updates**
   - [ ] Augment the embedding header (`include/protohack/native.h`) with helper
     macros to declare expected bindings.
   - [ ] Produce sample host code demonstrating how to assert bindings before
     marshalling data.
4. **Tooling/Docs**
   - [ ] Add `protohack-runner --inspect-native` to list native exports along
     with their binding requirements.
   - [ ] Document interop guidelines and pitfalls in the README (or a dedicated
     `docs/generics-interop.md`).
5. **Testing**
   - [ ] Integration test that loads a native extension expecting `T=num` and
     confirms mismatched callers are blocked.
   - [ ] Regression test ensuring symbolic bindings propagate through to the
     host when crafts remain partially specialized.

### Open Questions

- How do we surface binding expectations to languages without full ProtoHack
  type enums? (Proposal: expose both string labels and numeric tags.)
- Should native callbacks be allowed to *widen* bindings (accept broader types)
  via a capability flag, or must they match precisely?
- What is the deprecation path for existing native modules compiled before
  binding metadata existed?

## Next Milestone — Expression Typing & Flow Checks

Having established substitution, runtime dispatch, global controls, and interop
safety, the following milestone delivers full expression-level type validation
so generic misuse is caught during compilation rather than at runtime.

### Objectives

1. Annotate AST nodes with inferred or concrete `ProtoTypeTag` information
  generated during expression compilation.
2. Validate actual argument expressions against the expected generic bindings
  for both runtime crafts and native interop calls.
3. Surface precise diagnostics pointing to mismatched expressions, including
  the originating generic parameter and its required constraints.

### Typing Pipeline Enhancements

- **Inference context**: introduce a `TypeInferenceFrame` pushed alongside the
  compiler’s scope stack to track current bindings and expression types.
- **Constraint solving**: when an expression references a symbolic type, ensure
  it narrows consistently along conditional branches (e.g., type guards).
- **Error reporting**: reuse the binding metadata to format messages such as
  “`value` resolves to `text` but `T` for `identity<T>` was bound to `num`”.

### Work Breakdown

1. **AST Augmentation**
  - [ ] Extend expression nodes in `compiler/ast.h` (or equivalent) with a
      `ProtoTypeTag inferred_type` field.
  - [ ] Update constructors and serialization to preserve the new metadata.
2. **Compiler Passes**
  - [ ] Implement a `infer_expression_type` helper covering literals, variable
      references, calls, and control flow joins.
  - [ ] Integrate checks in `compile_named_call` and `compile_native_call` to
      validate arguments against specialization bindings.
3. **Diagnostics**
  - [ ] Add structured error objects to `core/error.c` for generic mismatches
      with contextual hints.
  - [ ] Provide fix-it suggestions when a missing specialization is detected
      (e.g., “add `<num>` at call site”).
4. **Tooling Integration**
  - [ ] Emit typing information in debug dumps so language servers can surface
      hover/type mismatches.
  - [ ] Add a compiler flag (`--dump-type-flow`) for visualizing inferred tags.
5. **Testing**
  - [ ] Unit tests covering simple successes, mismatched literals, and nested
      generics.
  - [ ] Flow tests ensuring branches correctly narrow or widen symbolic types.
  - [ ] Regression tests verifying diagnostics include the offending binding.

### Open Questions

- Do we need polymorphic recursion support now, or can it be deferred until a
  later milestone?
- How aggressively should we attempt type inference for unannotated crafts?
- What is the performance cost of tracking inferred types, and do we need an
  opt-out for release builds?

## Next Milestone — Developer Tooling & Diagnostics

With core semantics stabilizing, this milestone equips developers with
first-class tooling, ensuring generics issues are easy to understand and debug
across the entire workflow.

### Objectives

1. Deliver rich diagnostics (compiler, VM, runner) that surface binding and
   typing problems with actionable guidance.
2. Enhance IDE/server integrations with hover, go-to-definition, and refactor
   support for generic crafts and their specializations.
3. Provide runtime introspection commands so deployed systems can inspect
   active bindings and specialization caches without recompilation.

### Tooling Enhancements

- **Diagnostic catalog**: formalize error codes for generics-related failures
  with remediation tips and links to documentation.
- **Language server**: extend the ProtoHack LSP to report inferred types,
  specialization hierarchies, and inline quick-fixes.
- **Runtime shell**: add commands to the interactive debugger to list active
  specializations, show binding chains, and dump mismatched frames.

### Work Breakdown

1. **Compiler & Runtime Diagnostics**
   - [ ] Introduce structured diagnostic payloads carried through to the runner
         (JSON + localized string tables).
   - [ ] Ensure VM errors include the specialization fingerprint, binding diff,
         and call stack snippet.
2. **Editor Integration**
   - [ ] Update the LSP analyzer to consume the expression typing metadata and
         provide hover details for generic parameters.
   - [ ] Implement quick actions to insert missing type arguments or propagate
         bindings to dependent crafts.
3. **Inspection CLI**
   - [ ] Extend `protohack-runner` with `--dump-specializations` and
         `--trace-generics` modes.
   - [ ] Document usage with real-world troubleshooting scenarios.
4. **Documentation & Samples**
   - [ ] Publish a generics troubleshooting guide detailing common diagnostics
         and fixes.
   - [ ] Provide sample projects showcasing tooling integrations (editor + CI).
5. **Testing**
   - [ ] Snapshot tests covering diagnostic outputs for key failure modes.
   - [ ] Integration tests validating LSP responses for generic definitions and
         usages.

### Open Questions

- Do we need a dedicated generics dashboard inside the IDE, or are inline hints
  sufficient?
- How should diagnostics be localized—build-time resource bundles or runtime
  loading?
- What level of detail is safe to expose in production logs without leaking
  sensitive type information?

## Next Milestone — `extend` for Generic Crafts

We introduce a modern, declarative syntax for extending existing crafts with
additional behavior while preserving and refining their generic bindings. The
goal is to make mixin-style reuse ergonomic without sacrificing the safety
guarantees provided by the substitution pipeline.

### Syntax Summary

```
extend craft Vector<T> with Comparable<Vector<T>> {
  fn compare(other: Vector<T>) as Ordering {
    // ...
  }
}

extend craft Logger with Printable {
  fn print() as text { format("[LOG] {message}", message = self.message) }
}
```

- `extend craft Target<T, ...> with Trait<U, ...>` registers a block of members
  that becomes available when the target craft is specialized with bindings
  compatible with the trait constraints.
- Multiple `with` clauses form a comma-separated list; each generates a
  specialization check.
- The extension block can introduce:
  - Functions bound to `self`, observing the target’s visibility rules.
  - Stored properties declared with `let`/`const` that are hoisted into the
    target’s layout (subject to ABI gating).
  - Overrides marked with `override fn` when the target already defines a
    method signature.

### Objectives

1. Validate that `extend` blocks reference crafts whose generic bindings can be
   satisfied by the extension’s trait requirements.
2. Ensure specialization metadata records both the base craft bindings and the
   extension-provided members so downstream modules can enforce coherence.
3. Provide graceful diagnostics for conflicts (duplicate members, mismatched
   binding expectations, incompatible overrides).

### Work Breakdown

1. **Parser & AST**
   - [ ] Add `ExtendDeclaration` node capturing target craft, optional `with`
         clauses, and member block.
   - [ ] Support modern shorthand syntax such as method bodies without
         `return`, arrow functions for expression bodies, and trailing commas
         in `with` lists.
2. **Binding & Type Checking**
   - [ ] Reuse `ProtoTypeBindingSet` to evaluate whether the target craft’s
         bindings satisfy the extension’s trait parameters.
   - [ ] When traits introduce fresh parameters, surface them as additional
         constraints on the target specialization.
   - [ ] Disallow ambiguous overrides unless the extension explicitly narrows
         the signature with compatible generics.
3. **Code Generation**
   - [ ] Merge extension members into the target craft’s specialization during
         `ensure_craft_specialization`, emitting override stubs where needed.
   - [ ] Serialize extension metadata (source location, trait constraints,
         added members) alongside the base craft for tooling consumption.
4. **Runtime Integration**
   - [ ] Update VM craft instantiation to load extension members after base
         specialization, honoring override dispatch tables.
   - [ ] Include extension fingerprints in the specialization cache key so
         conflicting modules cannot silently diverge.
5. **Diagnostics & Tooling**
   - [ ] Emit targeted error codes for duplicate member names, missing trait
         implementations, or binding mismatches.
   - [ ] Extend the language server/LSP to surface extension provenance and
         quick-fixes (e.g., auto-inserting required trait members).
6. **Testing**
   - [ ] Unit tests covering: simple extension, generic refinement, trait
         conflicts, and override success/failure.
   - [ ] Integration tests verifying serialization/deserialization retains
         extension info.
   - [ ] VM runtime tests ensuring overridden methods resolve to extension
         implementations.

### Open Questions

- Should multiple `extend` blocks targeting the same craft merge sequentially
  or require explicit grouping?
- Do extension fields participate in the base craft’s constructor, and if so
  how are defaults expressed?
- How should we expose extension metadata to reflection APIs and tooling for
  debugging specialized crafts?

## Next Milestone — Global Generic Controls

With in-module specialization and runtime dispatch in place, the next phase is
to guarantee that generics behave consistently across module boundaries and
that `extend` declarations cannot violate their original contracts. This
milestone adds the compiler-and-tooling “global controls” that enforce type
safety regardless of where a specialization is emitted.

### Objectives

1. Detect and reject mismatched type arguments when a generic craft or class is
   referenced via serialized bytecode (`.phc`) or precompiled libraries.
2. Ensure that `extend` blocks inherit, propagate, and re-validate the type
   bindings of the entity they augment.
3. Provide deterministic diagnostics when a previously serialized specialization
   conflicts with the template definition in the current compilation unit.
4. Expose binding metadata through the tooling API so editors and analyzers can
   surface issues before compilation.

### Cross-Module Validation Strategy

- **Metadata contract**: Normalize bindings inside the serialized header so that
  every exported craft/class carries:
  - Template signature (base name, arity, type parameter labels).
  - Concrete binding set for the emitted specialization.
  - Source fingerprint/hash used to detect drift between producer and consumer.
- **Import verification**: During preprocessing of includes and bytecode
  imports, load the metadata, compare the template signature to the current
  definition, and surface a compile-time error on mismatch.
- **Lazy resolution cache**: Reuse the specialization table fingerprinting to
  short-circuit repeated validations inside large dependency graphs.

### `extend` Enforcement

1. Require explicit type arguments in the `extend` header; if omitted, emit a
   diagnostic asking the user to pick a concrete specialization.
2. Re-run the same binding compatibility checks used for imports, ensuring that
   the extended entity’s bindings exactly match the template definition.
3. Record the extension in a side table keyed by `(template fingerprint,
   binding set)` so downstream modules can validate the merged shape.

### Work Breakdown

1. **Metadata augmentation**
   - Extend the serializer to encode template fingerprints and binding sets.
   - Version the bytecode header to gate the stricter validation logic.
2. **Compiler guard rails**
   - Hook validation into `declare_global` / `class_declaration` when a symbol is
     resolved to an imported specialization.
   - Implement a dedicated diagnostic path for template drift and binding
     mismatches.
3. **`extend` pipeline**
   - Update parsing to require `extend Foo<num>` style headers.
   - Link the extension to the specialization table so additional methods share
     the same bindings.
4. **Tooling APIs**
   - Surface binding metadata through the protohack CLI/runner inspection
     command.
   - Add editor-friendly diagnostics (JSON or similar) to simplify IDE
     integration.
5. **Regression coverage**
   - Import a precompiled specialization with mismatched bindings → expect
     failure.
   - Extend a craft/class with missing/incorrect type arguments → expect failure.
   - Positive end-to-end scenario where a module extends a specialization and a
     consuming module imports both pieces.

### Open Questions

- How should we handle backward compatibility for bytecode generated before the
  fingerprint metadata existed? (Proposal: warn and allow with a `--legacy`
  flag.)
- Can we opportunistically relax the requirement for explicit type arguments in
  `extend` once import metadata supports inference? Leave this for a later
  iteration.

Clarifying these items up front keeps the global controls effort scoped and
provides a checklist to track progress before jumping into implementation.

## Appendix: Future Phases

- **Expression typing**: record `ProtoTypeTag` for each expression node to
  verify argument compatibility and return flows.
- **Runtime dispatch**: incorporate the binding set into VM call stubs so the
  runtime can select the correct specialization (or emit an informative
  runtime error when missing).
- **`extend` support**: treat `extend` blocks as templates that automatically
  specialize based on the receiver’s bindings.

---
This design is the agreed baseline for the substitution milestone.  Subsequent
work items will turn each checklist entry into concrete code, starting with the
parsing and binding changes.
