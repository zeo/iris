# iris

A firewall and network monitor for Windows. Iris watches every application's
network traffic and puts you in control of what is allowed to connect: per-app
allow and block rules, a live view of what every process is talking to, and a
running history of how much each one uses.

Built native: a small privileged engine (Windows service) does the real work
with the OS filtering platform and kernel network events, and an unprivileged
Tauri UI drives it over a local, access-controlled pipe. Monitoring and rules
keep running with the window closed.

## What it does

- **Protect** — per-app allow / block rules enforced at the Windows Filtering
  Platform, so a blocked app stays blocked whether or not the UI is open.
- **Activity** — a live table of every app's up / down rate, open connections,
  and the remote endpoints it is talking to.
- **Graph** — a scrolling picture of bandwidth over time, total and per app.
- **Usage** — rolling history of how much each app has sent and received,
  downsampled as it ages so the store stays small.
- **Alerts** — the first time a new program reaches the network, Iris flags it
  and raises a tray notification.

## Layout

```
crates/iris-core   platform-neutral models, engine traits, aggregation
crates/iris-ipc    framed wire protocol shared by the service and UI
service            the privileged Windows service (engine host)
app                the Tauri v2 + SolidJS desktop UI
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
drill-down and host names, the scrolling bandwidth graph, WFP allow/block rules,
usage history, first-seen alerts with tray toasts, and the background service.
