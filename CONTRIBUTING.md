# Contributing to Wiretap

## Principles

1. **Minimal code.** Write the smallest correct implementation. No placeholder modules, speculative abstractions or empty crates. A crate is added when its feature is built.
2. **Minimal, current dependencies.** Every dependency is attack surface. Add one only when no small, reviewable alternative exists, and disable default features. Use the newest release; `tools/check-latest.ps1` fails the build otherwise.
3. **Security first.** Treat every network byte, imported file, API request and addon message as hostile. Bound every buffer, count and loop. No panics on input: the workspace lints deny `unwrap`, `expect`, `panic` and unchecked indexing outside tests.
4. **Honesty.** Never present encrypted traffic as decrypted, and never claim support or a passing test without evidence.

## Rules for changes

- Write tests together with the code, including error paths, limits and malformed input.
- Every parser or decoder of untrusted bytes gets a fuzz target in `fuzz/` with seeds in `fuzz/corpus/<target>/`. Every fixed crash input goes to `fuzz/regressions/<target>/`.
- `unsafe` is allowed only at FFI boundaries (`wiretap-platform`, `wiretap-driver-client`, `driver/`), and every block needs a `// SAFETY:` comment.
- Kernel structure layouts in `driver/src/ffi.rs` must be asserted in Rust **and** in `driver/layout_check.c`.
- Don't increase the driver's capabilities without a written justification, a threat-model update, an authorization design, tests and documentation.
- Public items are documented: `missing_docs` is on.
- Don't edit an applied storage migration; add a new one.

## Before sending a change

Run the quality gates from [RELEASE.md](RELEASE.md#2-quality-gates), and the relevant fuzz targets for a few minutes.
