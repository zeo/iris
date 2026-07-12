# iris

A firewall and network monitor for Windows. Iris watches every application's
network traffic and puts you in control of what is allowed to connect: per-app
allow and block rules, a live view of what every process is talking to, and a
running history of how much each one uses.

Built native: a small privileged engine (Windows service) does the real work
with the OS filtering platform and kernel network events, and an unprivileged
Tauri UI drives it over a local, access-controlled pipe. Monitoring and rules
keep running with the window closed. Changing a firewall rule prompts for
elevation over a separate admin-only channel, so no unprivileged process can
rewrite what the system enforces.

## What it does

- **Protect**: per-app allow and block rules enforced at the Windows Filtering
  Platform, so a blocked app stays blocked whether or not the UI is open.
  Adding, removing, or toggling a rule asks for elevation.
- **Activity**: a live table of every app's up and down rate, open connections,
  and the remote endpoints it is talking to. Open a connection for its host name,
  network scope, country, and a one-click kill.
- **Graph**: a scrolling picture of bandwidth over time, total and per app, with
  live and historical ranges and a live split by adapter (Ethernet, Wi-Fi, VPN).
- **Usage**: rolling history of how much each app has sent and received, plus
  per-adapter totals, downsampled as it ages so the store stays small, with CSV
  export and an optional data-plan cap warning.
- **Alerts**: the first time a new program reaches the network, Iris flags it
  and raises a tray notification. Watched addresses raise a flag the moment
  anything contacts them.
- **Settings**: throughput units, notifications, launch at login, and one-click
  install or removal of the background engine.

Endpoint enrichment (network scope and the watchlist today, more via plugins)
is resolved in the engine and shown on the connection detail drawer.

Rules can be backed up to a JSON file and restored from one; a restore runs
through the same elevation gate as any other rule change, one prompt for the
whole file. To watch addresses, put one IP or CIDR per line (with `#` comments)
in `%ProgramData%\Iris\watchlist.txt`; matching endpoints get a danger badge and
an alert on first contact.

## Layout

```
crates/iris-core          platform-neutral models, engine traits, aggregation
crates/iris-ipc           framed wire protocol shared by the service and UI
crates/iris-platform-win  Windows backend: ETW capture, WFP filters, connections
crates/iris-store         SQLite history, usage rollups, and alerts
service                   the privileged Windows service (engine host)
app                       the Tauri v2 + SolidJS desktop UI
```

The engine is written against traits in `iris-core`, so the Windows backend and
a later Linux one are just two implementations behind the same surface.

## Building

Requires a recent Rust toolchain, Node, and pnpm.

```
cd app
pnpm install
pnpm tauri dev      # run the UI against a dev build
pnpm tauri build    # produce an installer
```

## Credits

IP-to-country data is DB-IP's [IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite),
licensed under CC-BY-4.0.

## Status

Working: the instrument shell, live per-app/per-process Activity with connection
drill-down, host names, and endpoint enrichment; the scrolling bandwidth graph
over live and historical ranges with a per-adapter split; elevation-gated WFP
allow/block rules with JSON backup and restore; usage history with per-adapter
totals and CSV export; first-seen and watchlist alerts with tray toasts; a
settings surface; and the self-installing background service with signed
auto-updates.
