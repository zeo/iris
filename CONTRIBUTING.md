# Contributing to Iris

Thanks for taking a look. Bug reports, fixes, and focused features are all
welcome.

## Repository shape

Iris is a Cargo workspace plus a ceri frontend:

- `crates/` holds the platform-neutral core, the IPC protocol, the Windows and
  Linux backends, the plugin SDK, and the SQLite store.
- `service/` is the privileged engine host (Windows service / systemd unit).
- `app/` is the ceri + SolidJS desktop UI. `app/src-ceri/` is its Rust side.

The host compiles the built pages in, so `pnpm build` runs before any cargo
command that builds `iris-app`. It looks for the engine at `engine/iris-engine`
beside its own executable, where a release package puts it.

## Building and running

You need a recent stable Rust toolchain, Node 22, and pnpm 9.

```
cd app
pnpm install
pnpm build          # the pages the host compiles in
cargo build --release -p iris-service -p iris-app
```

A debug build loads the pages from the Vite dev server instead, so run
`pnpm dev` next to `cargo run -p iris-app` and page edits apply without a
rebuild.

## Checks to run before a PR

CI runs on GitHub-hosted Windows and Ubuntu runners. It skips pull requests
from forks, so a fork PR gets no automated feedback. Run the same checks locally
before you open a PR:

```
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cd app && pnpm test && pnpm build
```

`pnpm build` runs `tsc --noEmit` and then a Vite build, so it catches type
errors too.

## Pull requests

Keep changes focused and the history readable: small commits, lowercase
imperative messages describing what the change does (for example
`fix stacked notification placement`). Explain what you changed and how you
tested it in the PR description. For anything security-sensitive, read
[SECURITY.md](SECURITY.md) and report privately instead of opening a PR that
discloses the issue.

By contributing you agree that your contribution is licensed under the same
terms as the project, MIT or Apache-2.0 at the user's option.
