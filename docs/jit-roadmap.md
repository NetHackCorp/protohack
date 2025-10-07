# Protohack JIT Roadmap

Bringing a real JIT (Just-in-Time compiler) to Protohack is a substantial project. This document lays out the technical approach in three incremental milestones so we can ship usable improvements quickly while keeping the long-term goal of native-speed execution in sight.

---

## Goals

1. **Runtime portability** – first target 64-bit Windows and Linux on x86-64, then abstract the backend for macOS and ARM once the design settles.
2. **Safety by construction** – the VM already operates on validated bytecode. The JIT must enforce the same invariants and never emit executable pages for untrusted payloads without validation.
3. **Interoperability** – compiled traces must share the same stack and heap layout as the interpreter so we can fall back seamlessly for unsupported instructions.
4. **Observability** – expose counters and diagnostic dumps so benchmarks and users can see what is optimized.

---

## Milestone 1 – Baseline tracing (Weeks 1–2)

_Outcome:_ Hot loops are executed by a lightweight super-instruction dispatcher, eliminating the giant `switch` in `protovm_run`.

- [x] **Bytecode profiler** – instrument the interpreter to count opcode frequencies and emit basic histograms (loop streak tracking TBD).
- [x] **IR builder** – translate basic blocks into a custom intermediate representation (IR) composed of arithmetic, stack, and control-flow nodes.
- [x] **Super-instruction cache** – encode IR blocks into compact structs (`ProtoJITBlock`) executed by a specialized threaded interpreter (computed goto / function-pointer table). This yields a measurable speedup without generating machine code yet.
- [x] **Fallback plumbing** – teach the VM to prefer compiled blocks and fall back to the classic interpreter if an opcode is missing in the IR backend.

_Metrics:_ Aim for ≥1.5× speedup on the `make perf` benchmark with IR dispatch enabled. Early measurements with the current threaded IR dispatcher land at ~0.34&nbsp;ms/run (≈2.9k runs/s) on the default harness, with further gains expected as we broaden opcode coverage.
Typed memory opcodes now execute inside the IR dispatch, and unsupported instructions report bailouts via the profiler to guide the next tranche of work.

---

## Milestone 2 – Native codegen MVP (Weeks 3–6)

_Outcome:_ Straight-line arithmetic blocks are emitted as real machine code for x86-64 (Windows + Linux).

- [ ] **Executable arena manager** – wrap `VirtualAlloc` / `mmap` helpers that reserve RWX memory with guard pages and deterministic lifetime tracking.
- [ ] **Registers & calling convention** – define a calling convention for JITed blocks (e.g. pass `ProtoVM *` in `rcx`/`rdi`, return new instruction pointer in `rax`).
- [ ] **Code emitter** – implement a tiny assembler that can emit the subset needed for: constants, arithmetic (`+`, `-`, `*`, `/`), comparisons, conditional jumps, and stack manipulation.
- [ ] **Deoptimization hooks** – emit guards before unsupported instructions; on guard failure, flush the stack state back to the interpreter and resume safely.
- [ ] **Testing harness** – extend `tests/test_perf.c` with toggles to compare interpreter vs JIT runtime and verify identical results (`proto_value_equal`).

_Metrics:_ ≥3× speedup on arithmetic-heavy loops when JIT is enabled.

---

## Milestone 3 – Advanced features (Weeks 7+)

_Outcome:_ Feature parity with the interpreter for the core language subset, plus tooling.

- [ ] **Typed memory ops** – generate native loads/stores for `carve`, `probe`, and `etch` sequences.
- [ ] **Native call bridges** – support calling built-in natives (`rand`, `hex_encode`, etc.) by marshalling arguments in registers/stack.
- [ ] **Garbage-safety** – integrate with `proto_value_copy` / `proto_value_free` lifetimes; ensure we never leak strings or typed memory when bailing out of JITed code.
- [ ] **Policy controls** – CLI/VM flags (`--jit`, environment variables) to toggle JIT, set optimization levels, or disable executable memory in high-security contexts.
- [ ] **Diagnostics** – optional dump of generated machine code via `jit disassemble` command and counters exported for the benchmark harness.

_Metrics:_ ≥5× speedup on targeted workloads, full conformance with existing tests, and new regression suite for JIT-specific bugs (guard exits, memory boundaries, native calls).

---

## Immediate next steps

1. Extend IR opcode coverage to native calls (`CALL_NATIVE`) and control-flow edges so common stdlib helpers stay in fast paths.
2. Use the new bailout histograms to drive opcode prioritization and add logging hooks for flaky runtime exits.
3. Sketch the executable arena API (allocation, protection toggles, lifetime rules) so Milestone&nbsp;2 has a concrete target.
4. Prototype the x86-64 calling convention for JITed blocks and list the minimal instruction set the assembler must emit.

With Milestone&nbsp;1 complete we can now focus on native code generation while using the profiler and IR caches to validate each incremental improvement.
