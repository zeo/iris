# Security policy

Iris runs a privileged engine (a Windows service or a systemd unit) and changes
firewall rules through an admin-only elevation channel. Bugs in that surface can
have real consequences, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Please report privately, not in a public issue. Use GitHub's private
vulnerability reporting: open the **Security** tab of this repository and choose
**Report a vulnerability**. That opens a private advisory visible only to you and
the maintainer.

Include what you need to make the problem concrete: affected component (engine,
IPC socket, elevation channel, plugin sandbox, updater, UI), platform and
version, reproduction steps, and the impact you think it has. A proof of concept
helps but is not required.

Expect an acknowledgement within a few days. Once a fix is ready it ships in a
tagged release with signed installers and the advisory is published with credit
if you want it.

## In scope

- The privileged engine and its local IPC socket.
- The elevation channel used for rule changes (UAC on Windows, polkit on Linux).
- The plugin sandbox and egress pinning.
- The signed auto-updater.

## Supported versions

Fixes land on the latest release. There are no long-term support branches while
the project is pre-1.0, so please test against the newest version before
reporting.
