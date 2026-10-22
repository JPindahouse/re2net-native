# Prototype privacy and data flow

This source snapshot has no installer, external telemetry upload, desktop input
logger, web account login or automatic update service. It is not enabled in a game.
The adapter defines a bounded local named-pipe protocol for a separate companion;
the companion and its peer network are not included. Protocol fields include
transient session/connection/boot identifiers and game-specific state, so there is
no claim that the protocol contains no identifying data.

If someone loads the prototype plugin, its worker writes persistent JSON-line
diagnostic files under `reframework/data/re2net/native-door/`, named with process
ID and monotonic tick. Records include connection identifiers, operation/request
IDs, role, phase, reason, timestamp, bounded details and channel counters. Each
process journal file is capped at 8 MiB; the queue holds at most 1024 lines of up
to 1024 bytes. Failed writes, queue loss and incomplete tails are possible. There
is no aggregate directory retention cap and no implemented log-disable control
in this snapshot. These files are diagnostics, not proven complete campaign logs.
They are not automatically uploaded by this native component. Review their
contents before sharing them; future integrated releases need user-controlled
retention, logging and their own network/data-flow disclosures.

The component does not collect desktop keystrokes, passwords or unrelated app
data or read/write save files. No real user's game logs or diagnostics are included
in this source repository. The two public boot fixtures use explicitly invented
stable strings; the test connection UUIDs are declared synthetic. No runtime
privacy behavior is established by compiling the source. Do not install this
unvalidated source prototype as a playable release.
