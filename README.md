# Protohack Language

Protohack is a middle-level programming language tailored for ethical hacking workflows. Version 0.2.0 ships a richer syntax, a native standard library, and quality-of-life tooling alongside the C-based compiler and virtual machine.

## What works today

- Global bindings with `let` and immutable `const`
- Numbers, booleans, `null`, and UTF-8 strings
- Arithmetic, comparison, logical `and`/`or`, and string concatenation
- Blocks, `if`/`else`, `while`, and `for` loops
- Native helpers such as `clock`, `rand`, `sqrt`, `len`, `upper`, `lower`, `to_string`, and variadic `println`
- Deterministic bytecode generation with a lightweight execution VM
- Bytecode serialization/deserialization to `.phc` files
- Packaging compiled bytecode into standalone executables via the Protohack runner stub
- Editor/tooling presets via `.clang-format`, `.clang-tidy`, `.editorconfig`, and `.gitignore`

## Quick start

### Requirements

- C11-compatible compiler (tested with GCC/Clang)
- `make`

### Build and test

```powershell
make
make test
```

> `make` builds both `protohackc.exe` (the compiler/CLI) and `protohack-runner.exe` (the embedding stub used for standalone executables).

### Compile a Protohack program

```powershell
./protohackc.exe examples/hello.phk --run
```

> Tip: On Unix-like systems, drop the `.exe` suffix.

The command above produces `examples/hello.phc` and runs it immediately, showcasing loops, string helpers, and multi-line output.

### Emit a standalone executable

```powershell
# Produce examples/hello.exe alongside the .phc artifact
./protohackc.exe --exe examples/hello.phk

# Custom output name and explicit runner stub
./protohackc.exe --exe --exe-out dist/hello.exe --runner protohack-runner.exe examples/hello.phk
```

The generated executable appends Protohack bytecode to `protohack-runner.exe`. When launched, the runner extracts the embedded payload and executes it on the VM without needing the source or `.phc` file.

## Language preview

```protohack
const name = "protohack";
let retries = 3;

for (let i = 0; i < retries; i = i + 1) {
	println("[" + to_string(i) + "]", upper(name));
}

let elapsed = sqrt(49) / 2;
if (elapsed > 3 and rand(10) > 5) {
	print "cooldown reached:";
	print elapsed;
}
```

This snippet demonstrates the new control flow, logical operators, native helpers, and string handling that make Protohack expressive while remaining approachable.

## Standard library cheat sheet

| Function | Arity | Description |
| --- | --- | --- |
| `clock()` | 0 | Seconds since the process started. |
| `rand(max?)` | 0–1 | Pseudo-random number in `[0,1)` or integer range `[0,max)`. |
| `sqrt(x)` / `pow(base, exp)` | 1 / 2 | Math helpers. |
| `len(value)` | 1 | Length of strings or formatted values. |
| `to_string(value)` | 1 | Returns a string rendering of any value. |
| `upper(text)` / `lower(text)` | 1 | Case conversion for strings. |
| `println(..args)` | 0–8 | Variadic print with automatic spacing and newline. |

## Project layout

```
protohack/
├── include/protohack/        # Public headers for the compiler and VM
├── src/                      # Compiler, VM, and CLI implementation in C
├── tests/                    # Minimal regression suite
├── examples/                 # Sample Protohack programs
├── README.md                 # You are here
├── Makefile                  # Build orchestration (no CMake required)
├── protohack_lang.toml       # Language manifest
├── .clang-format             # Formatting defaults for contributors
├── .clang-tidy               # Static analysis defaults
└── .editorconfig             # Cross-editor settings
```

## Next steps

1. Add user-defined functions and closures
2. Expand the VM with sandboxed network and filesystem primitives tailored for ethical hacking
3. Build a REPL and debugger for rapid prototyping
4. Ship a formatting/linting tool and editor integrations
5. Establish a package system for distributing vetted auditing routines

Contributions and feedback on the early compiler stages are welcome.
