# ProtoHack Generic Types Proposal

_Date: 2025-10-07_

## Motivation

ProtoHack now supports typed values (num, flag, text, raw, pointer, memory) along
with user-defined classes (`class`) and craft functions. Pointer support opened
the door for richer data structures, but ergonomic reuse of container-like
abstractions remains painful. Users must hand-roll variations of the same
pattern for different value categories. Introducing **generic type parameters**
provides a single definition that can be specialized at compile time, while
keeping the runtime dynamically typed.

## Goals

- Allow declaring type parameters for `craft` functions and `class`
  declarations.
- Enable ergonomic extension of existing generic definitions with a modern
  syntax consistent with the language.
- Preserve ProtoHack’s dynamic runtime model; generics resolve to `any`-typed
  slots internally, but keep type metadata for tooling, documentation, and
  future static checks.
- Maintain backward compatibility with existing scripts.

## Non-Goals

- Full static type checking or monomorphization in the VM.
- Generic constraints (e.g., `T extends pointer`). These may follow later.
- Template metaprogramming or compile-time evaluation beyond basic
  instantiation.

## Syntax Overview

### Function Generics

```protohack
craft identity<T>(value as T) gives T {
  yield value;
}

let num_id = identity<num>(42);
let str_id = identity<text>("proto");
```

### Class Generics

```protohack
class Box<T> {
  init(value as T) {
    this.value = value;
  }

  get() gives T {
    yield this.value;
  }
}

let num_box = Box<num>(21);
let text_box = Box<text>("data");
```

### Extending Generics

Introduce an `extend` keyword that mirrors `class` but targets an existing
specialization:

```protohack
extend Box<num> {
  double() gives num {
    yield this.value * 2;
  }
}
```

For functions, `extend craft` allows attaching helper specializations:

```protohack
extend craft identity<num>(value as num) gives num {
  yield value;
}
```

(*Future consideration:* unify `extend` rules once core semantics ship.)

## Parsing Changes

- New tokens: `TOKEN_EXTEND`, `<`, `>`, `TOKEN_TYPE`, `TOKEN_TEMPLATE`
  (reuse existing comparisons for `<`/`>`; ensure precedence is preserved).
- Update declaration grammar:
  - `craft_declaration` parses optional type parameter list.
  - `class_declaration` parses optional type parameter list.
  - `extend_declaration` handles `extend class_name<params>` blocks.
- Introduce AST representation for type parameter lists and actual template
  arguments (e.g., `ProtoTypeParameter`, `ProtoTypeArgument`).

## Compiler Strategy

1. **Parsing:** Store generics metadata on `ProtoFunction` / `ProtoClass`:
   - `uint8_t type_param_count;`
   - `ProtoTypeTag type_params[PROTOHACK_MAX_TEMPLATE_PARAMS];`
   - `ProtoTypeTag type_arguments[PROTOHACK_MAX_TEMPLATE_PARAMS];`

2. **Instantiation:** When encountering `Box<num>`, the compiler builds a
   specialization key (e.g., `Box<num>`) and reuses it if already emitted.
   Until monomorphization exists, these specializations simply tag the
   function/class name (e.g., `Box<num>` becomes an interned global called
   `"Box<num>"`).

3. **Runtime:** No VM changes initially. Instances retain dynamic behavior.
   Specialization keys ensure distinct globals per instantiation.

4. **Extensions:** `extend` resolves to a previously instantiated specialization
   and patches its prototype: effectively sugar for calling the existing
   `class`/`craft` name with the `<args>` suffix.

## Implementation Plan (Incremental)

1. **Lexer / Parser groundwork**
   - Add `extend` keyword; ensure `<`/`>` remain usable for comparison and
     template delimiters (disambiguate via context).
   - Allow empty template argument lists for future-proofing (`<>`).

2. **Symbol Resolution**
   - Intern specialization names using a helper: `format_template_name("Box",
     [PROTO_TYPE_NUM]) -> "Box<num>"`.
   - Update global resolution to treat the formatted name as canonical.

3. **Code Generation**
   - Emit specialized globals the first time they are referenced.
   - Reuse existing `class`/`craft` compilation paths but operate on the
     synthesized name and keep metadata for debugging.

4. **Extend Support**
   - Parse `extend` blocks and bind them to an existing specialization.
   - For classes: reopen compiled chunk, append methods.
   - For crafts: emit helper wrappers.

5. **Tooling & Tests**
   - Expand `tests/test_basic.c` with identity function, generic Box class, and
     `extend` usage.
   - Update documentation with usage examples and limitations.

## Risks & Mitigations

- **Name collisions:** Formatted specialization strings must uniquely encode
  types. Mitigate by using canonical type names matching `proto_type_tag_name`.
- **Parser ambiguity:** `<`/`>` already participate in binary relations. Use a
  lookahead strategy similar to pointer dereference to detect template
  argument lists.
- **Runtime overhead:** Instantiation currently duplicates code. Later
  optimization: share base chunk and store type arguments separately.

## Future Work

- Allow type constraints (e.g., `T : pointer`).
- Support higher-order generics (templates as arguments).
- VM metadata for type arguments, enabling runtime reflection.
- Bytecode de-duplication / monomorphization.

---

This document establishes a consistent syntactic and semantic direction for
ProtoHack generics. Implementation can proceed incrementally following the plan
above without breaking existing programs.
