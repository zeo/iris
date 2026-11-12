# Security policy

Iris runs a privileged engine (a Windows service or a systemd unit). It changes
firewall rules through an admin-only elevation channel, or through a stored
rule grant for a desktop account the user authorized once. Bugs in that surface
can have real consequences, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Please report privately, not in a public issue. Use GitHub's private
vulnerability reporting: open the **Security** tab of this repository and choose
**Report a vulnerability**. That opens a private advisory visible only to you and
the maintainer.

Include what you need to make the problem concrete: affected component (engine,
IPC socket, elevation channel, rule grant, state directory, plugin sandbox,
updater, UI), platform and version, reproduction steps, and the impact you think
it has. A proof of concept helps but is not required.

Expect an acknowledgement within a few days. Once a fix is ready it ships in a
tagged release with signed installers and the advisory is published with credit
if you want it.

## In scope

- The privileged engine and its local IPC socket.
- The elevation channel used for rule changes (UAC on Windows, polkit on Linux).
- The rule grant that lets an authorized desktop account change rules and
  approve or enable plugins without a prompt, and the file that stores it.
- The engine's state directory (`%ProgramData%\Iris` on Windows,
  `/var/lib/iris` on Linux) and its permissions. On Windows the engine refuses
  to start if that directory or anything in it is owned by an account other
  than SYSTEM or Administrators, or is a link.
- The plugin sandbox and egress pinning.
- The signed auto-updater and the installer it starts. A copy of Iris under
  Program Files (or `/usr` or `/opt` on Linux) never runs an installer from the
  user's profile.

## Supported versions

Fixes land on the latest release. There are no long-term support branches while
the project is pre-1.0, so please test against the newest version before
reporting.
