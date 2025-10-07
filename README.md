# Protohack Language

Protohack is a middle-level programming language tailored for ethical hacking workflows. Version 0.2.0 ships a richer syntax, a native standard library, and quality-of-life tooling alongside the C-based compiler and virtual machine.

## What works today

- Global bindings with `let` and immutable `const`
- Numbers, booleans, `null`, and UTF-8 strings
- Arithmetic, comparison, logical `and`/`or`, and string concatenation
- Blocks, `if`/`else`, `while`, and `for` loops
- Classes with initializers, fields, and methods using `this`
- Native helpers such as `clock`, `rand`, `sqrt`, `len`, `upper`, `lower`, `to_string`, and variadic `println`
- File encryption helpers (`encrypt_file`/`decrypt_file`) and complex-number math primitives (`complex_*` functions)
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

### Benchmark the VM

```powershell
make perf
```

> The performance harness runs a compiled script a configurable number of times (default: 1000) and reports total runtime, per-iteration latency, and throughput.

Enable the experimental JIT instrumentation by passing `JIT=1` to `make` (for example `make JIT=1 perf`). During or after a run you can dump opcode histograms by calling `protojit_profiler_dump(protovm_profiler(&vm), stdout);` from your own harness.

### Compile a Protohack program

```powershell
./protohackc.exe examples/hello.phk --run
```

> Tip: On Unix-like systems, drop the `.exe` suffix.

The command above produces `examples/hello.phc` and runs it immediately, showcasing loops, string helpers, and multi-line output.

#### Encrypt a text file in place

```powershell
./protohackc.exe examples/inplace_encrypt.phk --run
```

> The script prompts for the path to a `.txt` file, overwrites it with encrypted data, and prints the hexadecimal key needed to restore it later.

### Command-line options

`protohackc` ships with a few quality-of-life flags to streamline local workflows:

| Flag | Description |
| --- | --- |
| `--help` / `-h` | Display the built-in usage guide with available options. |
| `--version` / `-V` | Print the compiler version and exit. |
| `-o <file>` | Override the default bytecode output path. |
| `--run` | Execute the freshly compiled program on the embedded VM. |
| `--exe` | Bundle the bytecode with the runner stub to produce a standalone executable. |
| `--exe-out <file>` | Specify a custom path for the bundled executable. |
| `--runner <file>` | Use a custom runner stub when building executables. |
| `--jit-profile`* | Run the program and dump JIT hotspot statistics (requires a JIT-enabled build). |

\* When present, `--jit-profile` implies `--run` so the profiler can gather data.

### Friendlier error messages

Syntax and runtime errors now point directly at the offending line with a caret indicator and surrounding context:

```
examples/broken.phk:4:7: compilation error: Expect ')' after expression
	println("oops";
		 ^
```

The compiler still emits descriptive text, but the highlighted excerpt makes it easier to diagnose mistakes quickly.

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

### Classes in Protohack

```protohack
class Counter {
	init(start as num) {
		this.value = start;
	}

	inc() gives num {
		this.value = this.value + 1;
		yield this.value;
	}
}

let counter = Counter(10);
println(counter.inc()); // 11
counter.value = 42;
let bump = counter.inc;
println(bump()); // 43
```

This snippet demonstrates the new control flow, logical operators, native helpers, and string handling that make Protohack expressive while remaining approachable.

## Standard library cheat sheet

| Function | Arity | Description |
| --- | --- | --- |
| `clock()` | 0 | Seconds since the process started. |
| `sleep(ms)` | 1 | Pause execution for the specified number of milliseconds. |
| `rand(max?)` | 0–1 | Pseudo-random number in `[0,1)` or integer range `[0,max)`. |
| `rand_bytes(count)` | 1 | Deterministic pseudo-random raw memory buffer (max 1&nbsp;MB). |
| `sqrt(x)` / `pow(base, exp)` | 1 / 2 | Math helpers. |
| `len(value)` | 1 | Length of strings or formatted values. |
| `to_string(value)` | 1 | Returns a string rendering of any value. |
| `upper(text)` / `lower(text)` | 1 | Case conversion for strings. |
| `hex_encode(value)` | 1 | Lowercase hexadecimal encoding for strings, raw/text memory, or display values. |
| `hex_decode(text)` | 1 | Decode a hex string into raw memory for probing or XOR work. |
| `encrypt_file(input, output, key?)` | 2–3 | Encrypt an entire file with a streaming XOR cipher. Returns the hexadecimal key (auto-generated when omitted). |
| `decrypt_file(input, output, key)` | 3 | Decrypt a file that was produced by `encrypt_file` using the provided hexadecimal key. |
| `complex_add/sub/mul/div(ar, ai, br, bi)` | 4 | Complex arithmetic returning typed numeric memory `[real, imag]`. Use `probe numeric(result, index)` to inspect components. |
| `complex_abs(real, imag)` / `complex_exp(real, imag)` | 2 | Magnitude of a complex value or its complex exponential (returns `[real, imag]`). |
| `println(..args)` | 0–8 | Variadic print with automatic spacing and newline. |
| `read_line(prompt?)` | 0–1 | Reads a line from standard input, optionally displaying a prompt. Returns text or `null` on EOF. |

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
