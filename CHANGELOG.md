# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- A connection prompt can be answered for just the host it names, and for 1 hour or until the engine restarts. Other hosts and expired answers prompt again.
- Usage can block an app from one host in its history. A host name is blocked at each address it resolved to since the engine started, and the row shows it as blocked.
- On Windows the Alerts blocks filter lists connections Iris stopped, from block rules, lockdown, and ask mode, with the remote address, how many tries, and when it last happened. Repeated tries fold into one row; rows older than 30 days or past the newest 5000 are dropped.
- An app's data quota can slow the app instead of blocking it: once the quota is spent, upload and download are held to a set KB/s (or the app's own lower limit) until the period resets, then its own limits come back. Linux slows only uploads, and the download half pauses for an anti-cheat like any download limit.
- The Windows Firewall outbound warning has a Let Iris decide button that sets the default outbound action back to Allow on the blocking profiles, after one elevation prompt. A profile that group policy blocks is named instead, since a local change would not hold.

### Changed
- The wire protocol is now version 18. The setup updates the app and engine together.

## [0.2.2] - 2026-11-12

### Added
- Settings choose which info cards show: first-seen apps, watcher alerts, data quotas, paused download limits, and plugin alerts, each on its own switch. Allow and Block prompts always show.

### Fixed
- One decision card per app and direction. Answering it settles every connection that app was waiting on, instead of leaving a stack of older cards for the same app.
- Prompts for an app that no longer exists on disk (an updated Store app moves to a new folder) or that are over a day old are settled by the engine. Answering one no longer fails with "resource not found".
- Cards no longer flicker or replay their entrance when the stack refreshes.
- An error on a card stays inside the card and the Allow and Block buttons stay reachable.
- Right-clicking the app or a card no longer opens the browser menu.
- The main window opens dark straight away instead of flashing white while the page loads.

### Changed
- Windows releases ship only the shared installer: the online and offline setups and the signed package. The NSIS setup, the MSI, and the updater's latest.json are gone. Copies installed with an NSIS or MSI setup from 0.1.6 on move to the shared installer at their next update check; older copies need the new setup installed by hand.
- The Linux release no longer publishes updater metadata; the .deb, .rpm, and AppImage stay.

## [0.2.1] - 2026-11-12

### Fixed
- The Linux online and offline setups and the Linux shared installer package build again. 0.2.0 shipped without them because the packer rejected an ELF installer.

## [0.2.0] - 2026-11-11

### Added
- Download speed limits per app on Windows, enforced through the bundled WinDivert 2.2.2 driver. The driver loads only while at least one download limit exists and unloads with the last one.
- Download limits pause while Easy Anti-Cheat, BattlEye, FACEIT, or Vanguard is running, and a card says so; they come back when the game exits. Upload limits stay on.
- Upload speed limits per app: Windows QoS policies on Windows, flow marks and an htb class on Linux.
- Data quotas per app, per day, week, or month. An app that spends its quota is blocked until the period resets, with a card. The monthly data plan alert moved into the engine, so it fires with the main window closed.
- Rules scoped to a remote host, port, or network, and rules that expire after a set time.
- A firewall mode switch (Ask, Notify, Lockdown) in Settings and the tray, and per-network-profile rules and modes.
- Traffic recorded per remote host, and a live throughput graph in the tray icon.
- Watcher alerts for a changed app binary, a traffic spike, a first-seen domain, and a changed gateway.
- Activity shows each connection's own download and upload rate, and edits an app's download limit, upload limit, and data quota in place.
- A warning when history is kept in memory only, and when Windows Firewall blocks outbound connections by default on any profile, which would override iris's allows.
- `iris-engine --clear-firewall` removes every iris filter and speed limit while keeping saved rules.

### Changed
- Connection cards live in a window that exists only while a card is showing, at the bottom-right of the primary monitor. With no card up, nothing of iris sits over the desktop or a game.
- Decision cards stay until answered. Info alerts show as cards in the same stack instead of Windows notifications.
- The main window is built when opened from the tray and destroyed on close, so an idle tray costs one webview less.
- Ask and Lockdown denials survive reboots and engine crashes; uninstall removes every iris filter, QoS policy, and the WinDivert driver.
- The engine log rolls over at 10 MB while the service runs.
- The wire protocol is now version 17. The setup updates the app and engine together.

### Fixed
- The Windows service answers the UI again: the sample loop supervisor no longer blocks startup.
- Firewall rules stay in force after an ungraceful engine exit, and failed filter deletes are reported instead of hanging the admin channel.
- Rule scopes, lifetimes, and profile modes are sent in a shape the engine can decode.
- A client that falls behind the alert stream gets the pending decisions resent.
- Ask-mode denials queue with a bound and publish in batches; enrichment runs on one worker with a bounded queue; the watcher's domain cache is bounded.
- QoS PowerShell calls time out, and rule-lock waits no longer stall request handling.
- The gateway probe runs before the store lock is taken.
- Store writes fsync less under WAL, and unanswered first-seen alerts are capped at the newest 500.

### Security
- Rust dependencies updated, including rusqlite 0.41 for the bundled SQLite WAL fix; frontend moved to Vite 8 and Vitest 5; CI actions pinned to current commits and built on Node 22.

## [0.1.14] - 2026-08-23

### Fixed
- Throughput sampling survives suspend/resume: rates no longer spike after a clock step, out-of-order ticks no longer stall the live view, and the sample loop no longer shares a reactor with request handling.
- A stalled byte-capture session is detected and restarted automatically; the interface shows a clear degraded state while capture is down and clears it when traffic resumes.
- Firewall rule changes keep working after a poisoned rule-store lock on the admin channel and in the desktop UI.
- The Linux engine restarts only after enforcement stays unhealthy, instead of tearing down on a single bad health sample.
- Elevated rule operations time out instead of hanging forever when the engine stops answering.
- The update check gives up after 30 seconds instead of waiting on a hung installer subprocess.
- Plugin panels back off to slow retries when a plugin stops responding, with a message that names the likely cause.
- The first live tick lands immediately after an engine reconnect, and the degraded-capture banner clears when the engine goes offline.

## [0.1.13] - 2026-08-17

### Fixed

- Network connection prompts stay topmost and visible without losing z-order or falling behind active applications.
- Connection alert publishing captures immediate baseline on startup without initial delay, and optimizes drop deduplication.
- Safe merging of incoming prompt decisions eliminates race conditions in the connection alert stack.
- Restore all pending prompt alerts across engine reconnects and restarts.

## 0.1.12 - 2026-08-12

### Fixed

- Network prompts appear without taking focus from the active application.

## 0.1.11 - 2026-08-12

### Fixed

- Pending network prompts return as soon as the desktop host reconnects to the engine.
- Windows network-event subscriptions close before their WFP engine handle.

## [0.1.10] - 2026-07-26

### Fixed

- Shared package signing resolves release artifacts from the repository root.

## [0.1.9] - 2026-07-26

### Fixed

- Shared installer packages use Iris's existing updater signer, including legacy keys that the standalone pack tool cannot open.

## [0.1.8] - 2026-07-26

### Fixed

- A connection prompt already answered by another Iris window now closes instead of showing a stale-decision error.

## [0.1.7] - 2026-07-26

### Fixed

- Sign the application executable before building shared installer packages.

## [0.1.6] - 2026-07-26

### Changed

- Updates now use the shared signed installer; this release carries the one-time bridge from the existing NSIS and MSI channels.
- Allow and Block answers from a live connection prompt now apply through the running engine on both platforms. Windows no longer opens a UAC dialog for that bounded decision.

### Fixed

- A saved Windows rule for an uninstalled application no longer leaves the service marked as running with no working engine. The rule stays enabled and is applied when the executable returns.
- The Windows service reports startup failures to the Service Control Manager, waits for the Base Filtering Engine at boot, reapplies protected state permissions, and reports service-start failures to the installer.

## [0.1.5] - 2026-07-18

### Added

- The Activity table sorts through real buttons that report the current sort to a screen reader, and its connection rows are focusable and open on Enter or Space, so sorting and the per-connection inspect and kill flow work without a mouse.
- The connection consent prompt is now announced as an alert dialog, and its waiting or failed firewall status is read aloud as it changes.
- Segmented filter and action toggles report their pressed state, and the app and activity search boxes have accessible names.

### Fixed

- The protect decision menu and the settings number fields show a visible focus ring again when reached by keyboard.
- Section micro-labels now meet the small-text contrast minimum in both themes.

## [0.1.4] - 2026-07-16

### Security

- Blocking a connection from a prompt on Windows now goes through the elevated channel; the unprivileged telemetry channel can no longer install a firewall filter on its own.
- Out-of-process plugins on Windows run inside a kill-on-close job object and with only the standard system environment, so a plugin cannot outlive the service or read variables it inherited.
- The unprivileged control channel no longer runs database or firewall work on the async reactor, closing a local denial-of-service path against the engine.

### Changed

- DNS response capture applies its port-53 filter in the kernel, so the engine wakes only for DNS traffic instead of every packet on the host.
- Less work per sampling tick in the connection monitor and tracker.

### Fixed

- The data-plan meter refreshes as soon as you set a cap or the engine connects instead of staying blank for a few minutes.
- Plugin panels no longer blank and redraw every few seconds when their data has not changed.
- Alert Allow and Block buttons act on their own row instead of disabling every pending decision at once.
- The Activity list keeps TCP and UDP connections that share addresses and ports on separate rows.
- The Known apps list and the Plugins tab show a "waiting for the engine" state while the service is unreachable instead of appearing empty.

## [0.1.3] - 2026-07-16

### Added

- Webview zoom hotkeys (Ctrl +/-/0 and Ctrl+scroll) so the interface can be scaled on small or high-density displays.

### Fixed

- Connections from apps that send the instant they open a socket (games, short-lived requests) are now attributed and prompted instead of being dropped with no prompt.
- The main window no longer clips its right edge on Linux displays that use fractional scaling.
- The connection prompt anchors to the monitor the main window is on and re-applies its position after the window maps.

## [0.1.2] - 2026-07-16

First public release.

### Added

- First public release of iris, a native firewall and network monitor for Windows and Linux.
- MIT and Apache-2.0 license files, a NOTICE for the bundled DB-IP data, and contributor, security, and code-of-conduct docs.

### Fixed

- Connection prompts and notifications now place correctly under fractional
  webview scaling on Windows and Linux, and no longer clip or stack past two
  cards.
- Duplicate connection notifications are suppressed.

## [0.1.1] - 2026-07-15

### Fixed

- AppImage runtime tooling and packaging fixes.

## [0.1.0]

Initial tagged build.

[Unreleased]: https://github.com/zeo/iris/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/zeo/iris/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/zeo/iris/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/zeo/iris/compare/v0.1.14...v0.2.0
[0.1.14]: https://github.com/zeo/iris/compare/v0.1.13...v0.1.14
[0.1.13]: https://github.com/zeo/iris/compare/v0.1.10...v0.1.13
[0.1.10]: https://github.com/zeo/iris/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/zeo/iris/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/zeo/iris/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/zeo/iris/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/zeo/iris/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/zeo/iris/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/zeo/iris/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/zeo/iris/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/zeo/iris/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/zeo/iris/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/zeo/iris/releases/tag/v0.1.0
