# Diagnostic Localization Strategy

_Last updated: 2025-10-10_

This document sketches the approach for localizing ProtoHack compiler and
runtime diagnostics, covering string catalog design, tooling, and rollout
phases.

## Goals

- Provide localized diagnostic messages (errors, warnings, hints) without
  sacrificing structured metadata.
- Allow SDKs and CLI tools to select locale at runtime via environment
  variable or CLI flag.
- Keep existing English copy as the authoritative source while enabling
  translation contributions.

## Scope

- Compiler diagnostics emitted through `ProtoError`.
- Runtime diagnostics surfaced by `protovm_run`, native bridge failures,
  and tooling commands (e.g., `protohack-runner`).
- Excludes user-authored messages (e.g., `print "Hello"`).

## Proposed Architecture

| Component | Description |
| --- | --- |
| String catalog | JSON or TOML catalog mapping diagnostic keys to localized strings per locale (e.g., `en-US`, `fr-FR`). |
| Diagnostic payload | Continue emitting structured payloads with `messageKey`, `hintKey`, and parameters; renderer resolves into locale-specific text. |
| Locale selection | CLI flag `--locale <code>` overriding environment variable `PROTOHACK_LOCALE`; defaults to `en-US`. |
| Build tooling | Script to validate catalog completeness and detect unused keys. |

### Data Flow

1. Compiler emits `ProtoError` with `message_key`, `hint_key`, and
   arguments.
2. Presentation layer (CLI, IDE plugin) loads catalog for requested locale.
3. Renderer formats string using localized template + parameters; falls
   back to English if key or locale missing.

## Implementation Steps

1. **Catalog format**
   - Select JSON for ease of tooling integration.
   - Define schema: `{ "locale": "en-US", "messages": { "code": "..." }, "hints": { ... } }`.
2. **Runtime selection**
   - Implement locale resolver utility (`protohack_locale_resolve`).
   - Update CLI (`src/main.c`) to accept `--locale` flag.
3. **Renderer**
   - Add helper to map `ProtoError` keys to localized strings with printf-style
     interpolation.
4. **Tooling**
   - Create `make lint-locales` target to verify catalog coverage.

## Risks & Mitigations

- **Missing translations**: Use English fallback and log warning once per
  missing key.
- **String drift**: Require translation sync as part of release checklist;
  add CI check to ensure English catalog updated alongside code changes.
- **Performance**: Cache catalog in memory to avoid repeated disk I/O.

## Open Questions

- Preferred templating syntax for translators (printf vs. brace format)?
- Need pluralization support out of the gate? (Initial assumption: no.)
- How should SDKs bundle locale catalogs for offline environments?

## Next Actions

- [ ] Review architecture with developer experience team.
- [ ] Prototype catalog loader + renderer.
- [ ] Draft localization contribution guidelines.
