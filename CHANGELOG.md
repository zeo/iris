# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
