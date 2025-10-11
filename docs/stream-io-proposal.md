# Protohack Flow System Proposal

This proposal supersedes the earlier C++-style stream plan. Instead of mimicking `std::cout`/`std::cin`, Protohack will introduce its own **Flow** concept for structured data transport. The design avoids implicit global streams and offers a composable pipeline syntax tailored to the language.

## Guiding Principles

- **No implicit globals**: users construct flows explicitly rather than relying on `stdout`/`stderr` singletons.
- **Pipeline syntax**: reading/writing resembles data routing (`emit`, `route`, `capture`) rather than operator chaining.
- **Extensible endpoints**: files, memory buffers, network sockets or user-defined adapters can participate in a flow graph.
- **Deterministic ownership**: flows must be explicitly started/stopped, making lifecycle management visible in user code.
- **Error transparency**: operations return tagged results instead of mutating hidden status flags.

## Vocabulary

- **Flow**: the runtime object managing a sequence of frames (messages) travelling from sources to sinks.
- **Source**: produces frames (e.g. file reader, user input callback).
- **Sink**: consumes frames (e.g. file writer, console view, memory collector).
- **Stage**: optional transformer between source and sink (e.g. map, filter, buffer).

## Surface Syntax Sketch

```protohack
// Declare a flow template
flow logFlow {
  source capture_input();           // craft returning text frames
  stage map format_timestamp;       // apply craft to each frame
  sink   append_file("logs.txt");  // native sink writing to disk
}

// Start and interact with the flow
let logger = logFlow.launch();
emit logger <- "Server starting";
emit logger <- "Listening on port 9000";
stop logger;                        // flush + release resources

// Reading pipeline example
flow numbers {
  source read_file("values.csv");
  stage  map parse_num;
  sink   to_array();
}

let pipeline = numbers.launch();
let { ok, data } = drain pipeline;  // consumes until source exhaustion
```

### Flow Blocks

```
flow <Identifier> {
  source <expr>;
  stage  <expr>;      // zero or more
  sink   <expr>;
}
```

- `source`/`stage`/`sink` keywords are mandatory in order.
- Each expression must evaluate to a compatible component (craft or native factory returning a `FlowComponent`).
- The block compiles to a reusable closure capturing the component definitions.

### Runtime Interaction

- `launch()` returns a `FlowHandle` with crafts:
  - `emit handle <- value;` enqueue frame for downstream processing.
  - `pull handle -> target;` retrieve next frame from sink output queue.
  - `drain handle` collect all remaining frames (returns `{ ok, data, error }`).
  - `stop handle` gracefully terminates the pipeline.
- Backpressure: `emit` suspends when downstream buffers are full; `pull` suspends until data is available.
- Errors propagate as tagged unions: `{ ok: false, error: <code>, message: <text> }`.

## Language Support Requirements

1. **New keywords**: `flow`, `source`, `stage`, `sink`, `emit`, `pull`, `drain`, `stop`.
2. **Grammar additions**:
   - Flow block declaration.
   - Binary operators `<-` (flow send) and `->` (flow receive) with assignment-like precedence.
3. **Runtime types**:
   - `FlowTemplate`: immutable compiled representation of a flow block.
   - `FlowHandle`: live instance managing execution state.
   - `FlowComponent`: interface implemented by sources/stages/sinks (native or user crafts).
4. **Scheduling**: lightweight cooperative scheduler executing flow stages sequentially per frame.
5. **Standard library**: bundled components for common scenarios (file read/write, console, timers).

## MVP Feature Matrix

| Capability | Included | Notes |
| --- | --- | --- |
| Flow declaration + launch | ✅ | Single source, optional stages, single sink |
| Emit / Pull / Drain / Stop | ✅ | Blocking semantics for now |
| Components | ✅ | `capture_input`, `append_file`, `read_file`, `to_array`, `map craftRef` |
| Error propagation | ✅ | Tagged record `{ ok, data?, error? }` |
| Concurrency | ❌ | Single-threaded execution; concurrent flows handled cooperatively |
| Stream reuse | ✅ | Flow templates reusable multiple times |
| Dynamic stage insertion | ❌ | Only static configuration in the flow block |

## Component Contracts

| Role | Required crafts | Description |
| --- | --- | --- |
| Source | `next()` → `{ done: bool, value?: any }` | Produces next frame or signals completion |
| Stage  | `transform(frame)` → `{ ok: bool, value?, error? }` | Returns transformed frame or failure |
| Sink   | `push(frame)` → `{ ok: bool, error? }` / `collect()` → array | Accepts frames and optionally exposes collected output |

All components may implement `close()` for cleanup; the runtime invokes it during `stop`.

## Runtime Architecture

1. **FlowTemplate Compilation**
   - During parsing, capture AST of component expressions.
   - At runtime, evaluate each expression when `launch()` is called.
2. **Execution Engine**
   - Maintain a queue of pending frames.
   - Processing loop: `frame -> stage1 -> stage2 -> ... -> sink`.
   - Sinks with pull semantics store frames for later retrieval via `pull`/`drain`.
3. **Backpressure & buffering**
   - Provide configurable max queue length (default 64 frames).
   - `emit` returns `{ ok: false, error: "FLOW_FULL" }` if buffer saturated.
4. **Error propagation**
   - Any component returning `{ ok: false }` stops the flow and surfaces the error on subsequent API calls.

## Example Components

```protohack
craft capture_input() gives FlowSource {
  let buffer = [];
  yield FlowSource {
    next() {
      if (buffer.count() == 0) {
        let line = read_line();
        if (line == null) {
          return { done: true };
        }
        buffer.push(line);
      }
      return { done: false, value: buffer.shift() };
    }
  };
}

craft append_file(path as text) gives FlowSink {
  let handle = file_open(path, "append");
  yield FlowSink {
    push(frame) {
      let ok = file_write(handle, frame);
      return ok ? { ok: true } : { ok: false, error: "IO_WRITE_FAILED" };
    },
    close() {
      file_close(handle);
    }
  };
}
```

## Documentation & Tooling Impact

- Update language reference with new keywords and flow syntax.
- Extend IntelliSense to suggest flow keywords, recognise `<-` / `->` usage, and surface component contracts.
- Provide example scripts in `examples/flows/` demonstrating logging pipeline, CSV ingestion, and memory buffering.

## Open Questions

- Should flows support branching (multiple sinks) in the MVP?
- How to integrate asynchronous/native event sources (e.g. socket reads) without blocking the VM?
- Should the flow scheduler expose hooks for instrumentation/monitoring?
- How to sandbox native components to prevent blocking the VM for long operations?

## Next Steps

1. Finalise syntax decisions (especially behaviour of `<-` / `->`).
2. Prototype parser changes and add baseline tests for flow blocks.
3. Implement minimal runtime engine with `capture_input`, `to_array`, and `append_file` components.
4. Produce a tutorial covering flow definition, launch, emission, and draining.
