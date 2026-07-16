# Contributing to Iris

Thanks for taking a look. Bug reports, fixes, and focused features are all
welcome.

## Repository shape

Iris is a Cargo workspace plus a Tauri frontend:

- `crates/` holds the platform-neutral core, the IPC protocol, the Windows and
  Linux backends, the plugin SDK, and the SQLite store.
- `service/` is the privileged engine host (Windows service / systemd unit).
- `app/` is the Tauri v2 + SolidJS desktop UI. `app/src-tauri/` is its Rust side.

The desktop bundle builds the release engine and embeds it as a Tauri resource,
so `pnpm tauri build` runs `cargo build --release -p iris-service` first.

## Building and running

You need a recent stable Rust toolchain, Node 20, and pnpm 9. On Linux you also
need the usual Tauri system dependencies (GTK, WebKitGTK, and the AppImage
tooling); see the Tauri prerequisites for your distribution.

```
cd app
pnpm install
pnpm tauri dev      # run the UI against a dev build
pnpm tauri build    # produce an installer
```

## Checks to run before a PR

CI runs on private self-hosted runners and does not execute on pull requests from
forks, so it will not give you automated feedback. Run the same checks locally
before you open a PR:

```
cargo test
cargo clippy --all-targets -- -D warnings
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
