# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.3]: https://github.com/zeo/iris/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/zeo/iris/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/zeo/iris/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/zeo/iris/releases/tag/v0.1.0
