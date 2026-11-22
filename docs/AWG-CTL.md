# awg-ctl

The plugin's one process. A client only: each
tunnel is one device with one peer, its endpoint an address and a port.
No pages, no DNS, no server side.

## Its life

The channel is routeh-plugin-sdk's (`Awg` is its `Plugin`): the socket,
`hello`, `desired` in, `state` out when it changed, `ping`, SIGTERM, the
system log. What is the plugin's:

- Each `desired` is converged by the engine (`engine.rs`) over the
  module's netlink (`kernel.rs`).
- Every 5 s it converges again (`tick`): what is right costs a dump, what
  was changed or removed behind its back is put back.
- When stopped it removes its devices. A crash removes nothing: procd
  starts it again, it is told the applied `desired`, and finds its devices
  as they are.
- Logs go to the system log as `awg` and `awg/<key>`, only when something
  changes (an error appearing or going, a device removed).

## What it reads

`plugin/manifest.toml` is the schema; `crates/awg-ctl/src/config.rs` reads
it, each value as the router writes it into `desired` (as its configuration
writes it): keys in base64 of 32 bytes, ranges `"lo-hi"` (also
`{"lo", "hi"}` or one number), durations `"25s"`, `"1m"`, `"2h"` (or
seconds). A key it does not know is an error. `tests/plugin.rs` checks
the manifest is one the router installs, and that every value awg-ctl
reports is one the manifest declares, of its type.

The endpoint is the router's `host_port`, which takes a name; there is no
DNS in the plugin, so a name is refused at the apply (`endpoint
"vpn.example:51820" names a host; … write its address`). `"ip:port"` or
`"[ip6]:port"`.

Allowed IPs are always `0.0.0.0/0, ::/0`: WireGuard's allowed IPs filter
what one peer may send and choose the peer for a packet; with one peer
they choose nothing, and what goes into the tunnel is the router's routing.

Everything the module would refuse or misuse is refused before anything is
sent, with a message naming the field (`docs/NETLINK.md`): Jmin above Jmax,
H ranges overlapping or backwards, S below 12 with a header protection key,
a template the module would read otherwise.

## How it converges a tunnel

| Found | Done |
|---|---|
| no device | made, read, configured |
| a device of another kind by that name | `error`, untouched |
| the device with a header protection key that `desired` no longer has | removed and made again (the key cannot be cleared) |
| the device | only what differs is sent |
| a device `tn_*` of the module's kind no tunnel names | removed |

Only what differs: the private key, the port, the mark, the obfuscation
whole, and the peer changed in place (preshared key, endpoint, keepalive,
allowed IPs), so a session survives an update of something else. A new peer
key replaces the peer.

- **Endpoint**: the dump shows where the peer was last heard from. The
  configured endpoint is sent again only when it changed in `desired`; a
  peer that roamed stays where it went. After a restart there is no memory
  of what was sent, and a roamed endpoint is set back once.
- **Port**: no port lets the module pick one. Going from a port to none
  sends 0 once; after that the picked port is kept.
- A refused configuration leaves the device as it was and reports `error`.
  Other tunnels go on.

## What it reports

Plugin: `tunnels_up` (count), `module_version` (from
`/sys/module/amneziawg/version`, or the bundle's `build.json` on OpenWrt).

Each tunnel:

| Phase | When | Message |
|---|---|---|
| `starting` | the device is not there yet | `making the device` |
| `connecting` | configured, no handshake within the window yet | `waiting for the first handshake` |
| `up` | a handshake within the window | |
| `down` | it was up, the last handshake is older than the window | `no handshake for more than N s` |
| `error` | refused configuration, missing module, a device it may not touch | the reason |

The window is 180 s (WireGuard's `REJECT_AFTER_TIME`), or the upper end of
`reject_after_time` when it is set. `peer` is the address from the dump.
Values: `public_key` (to give to the server), `listen_port` (the one in
use), `last_handshake` (a moment, so the state does not change every
second).

## What it relies on

- The router names every tunnel's device `tn_<key>` (`DEVICE_PREFIX`) and
  makes no other device of the module's kind with that prefix: the plugin
  removes such a device as its own leftover.
