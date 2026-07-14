# iris

A firewall and network monitor for Windows and Linux. Iris watches application
network traffic and puts you in control of what is allowed to
connect: per-app allow and block rules, a live view of what every process is
talking to, and a running history of how much each one uses.

Built native: a small privileged engine (a Windows service, or a systemd unit on
Linux) does the real work with the OS filtering layer and kernel network events,
and an unprivileged Tauri UI drives it over a local, access-controlled socket.
Monitoring and rules keep running with the window closed. Changing a firewall
rule prompts for elevation over a separate admin-only channel (a UAC prompt on
Windows, a polkit prompt on Linux), so no unprivileged process can rewrite what
the system enforces.

## What it does

- **Protect**: per-app allow and block rules, so a blocked app stays blocked
  whether or not the UI is open. Windows enforces them at the Filtering Platform;
  Linux decides each new connection in the engine behind an nftables queue.
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
- **Plugins**: optional extensions run out of process in a restricted sandbox,
  with capabilities limited to the powers you approve. A plugin can annotate endpoints, raise
  alerts, suggest firewall rules for your review, and show its own panel tab.
- **Settings**: throughput units, notifications, launch at login, and one-click
  install or removal of the background engine.

Endpoint enrichment (network scope and the watchlist today, more via plugins)
is resolved in the engine and shown on the connection detail drawer.

Rules can be backed up to a JSON file and restored from one; a restore runs
through the same elevation gate as any other rule change, one prompt for the
whole file. To watch addresses, put one IP or CIDR per line (with `#` comments)
in the watchlist file (`%ProgramData%\Iris\watchlist.txt` on Windows,
`/var/lib/iris/watchlist.txt` on Linux); matching endpoints get a danger badge
and an alert on first contact.

## Plugins

Iris extends through out-of-process plugins rather than code in the engine. A
plugin is a normal executable installed under the plugins directory
(`%ProgramData%\Iris\plugins\<id>\` on Windows, `/var/lib/iris/plugins/<id>/` on
Linux) with a `plugin.json` manifest declaring what it wants: capabilities (observe
traffic, annotate endpoints, raise alerts, suggest rules, show a panel) and the
exact hosts it needs to reach. Nothing runs until the user reviews that
declaration in the Plugins tab and enables it.

The sandbox is enforced by the service, not trusted to the plugin. On Windows
each child runs under a restricted low-integrity token with every privilege
stripped; on Linux it runs as a dedicated unprivileged account with no new
privileges and capped resources. Its network access is pinned to consented
endpoints through the Filtering Platform on Windows and a private cgroup-v2
nftables boundary on Linux. Linux plugins share one sandbox account while
retaining separate network grants; an empty egress list means no network at all.
A plugin cannot change firewall rules. The strongest thing it can do is file a
rule proposal, which sits in Protect until the user accepts it through the same
elevation gate as a manual rule. Panels are declarative: a plugin returns data
widgets and the UI renders them with its own primitives, so no plugin code ever
runs in the interface.

Plugin authors implement one trait from the `iris-plugin` crate and call
`run()`; the SDK handles the pipe, the handshake, and delivery.

## Layout

```
crates/iris-core          platform-neutral models, engine traits, aggregation
crates/iris-ipc           framed wire protocol shared by the service and UI
crates/iris-platform-win  Windows backend: ETW capture, WFP filters, connections
crates/iris-platform-linux Linux backend: sock_diag, NFQUEUE, nftables, systemd
crates/iris-plugin        the SDK plugin authors build against
crates/iris-store         SQLite history, usage rollups, and alerts
service                   the privileged Windows/systemd engine host
app                       the Tauri v2 + SolidJS desktop UI
```

The engine is written against traits in `iris-core`; Windows and Linux provide
platform implementations behind the same service surface.

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
allow/block rules on Windows and Linux with JSON backup and restore; usage history with per-adapter
totals and CSV export; first-seen and watchlist alerts with tray toasts; the
sandboxed plugin runtime with consent, egress pinning, rule proposals, and panel
tabs; a settings surface; and the self-installing background service with signed
auto-updates.
