## Documentation and code quality

- Prefer working code over documentation about the code.
- Keep documentation minimal, factual, and useful.
- Do not create documentation files unless explicitly requested or required to understand, build, or use the software.
- Do not create ADRs, implementation summaries, phase reports, progress logs, or planning documents by default.
- Do not document obvious implementation details that can be understood directly from the code.
- Use the README for installation, development commands, and essential project information.
- Document complex behavior close to the relevant code.
- Update existing documentation instead of creating new files.
- Do not repeat the same information across multiple files.
- Treat Git history, issues, and pull requests as the record of development.
- Keep comments minimal. Explain non-obvious behavior, constraints, and workarounds, not what the code already expresses.
- Avoid speculative abstractions, placeholder implementations, and unnecessary boilerplate.
- Before finishing, remove redundant comments, unused abstractions, and documentation that adds no practical value.
- Report implementation results in the final response, not in committed Markdown files.

Write documentation for developers who need to use or maintain the software, not to demonstrate that work was completed.

## Project rules

- Leonida Forge targets GTA VI only. Treat its file formats, natives and scripts as unknown until verified. Never invent format details, archive entries or research results.
- Tests MUST use synthetic data. Never commit game files or data extracted from them.
- Crate boundaries:
  - `crates/core` MUST NOT depend on GPUI or wgpu.
  - `crates/renderer` MUST NOT depend on GPUI.
  - `apps/cli` MUST NOT initialize GPUI or wgpu.
- GPUI comes from a pinned Zed git revision. Bump `gpui` and `gpui_platform` together, and check Zed's `[patch.crates-io]` for entries that the root `Cargo.toml` must mirror.
- File access MUST be read-only. Never write to, rename or delete anything inside a workspace root. Settings go to `%APPDATA%` only.
- Keep the desktop UI thread free of blocking work. Filesystem access, image decoding and rendering run on background threads.
- Before committing, run the CI checks: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Commit messages follow Conventional Commits.

## Development workflow

Development is feature-driven.

- The user defines or approves a feature. Implement it from the established format knowledge when that knowledge exists.
- A numbered research backlog is knowledge, not a queue. Do not start a research iteration on your own.
- When a missing fact blocks a feature, name that fact precisely and propose a focused research request for approval. Do not invent behavior to avoid the request.
- State a capability for what it is: recognized, structurally inspected, parsed, integrity verified, decoded, reconstructed at byte level, partial, ambiguous, unsupported, malformed or not evaluated. A structural parse is not a semantic decode.
