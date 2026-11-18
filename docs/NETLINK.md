# The AmneziaWG module over netlink

What `crates/awg-netlink` relies on, read from amneziawg-linux-kernel-module
`63ed35de` (3.1.20261113-02): `src/uapi/wireguard.h`, `src/netlink.c`,
`src/device.c`, `src/junk.c`, `src/send.c`, `src/type.h`. Each point says
where it is in the source and what the crate does about it.

## The interface

- Generic netlink family `amneziawg`, version 3. Commands
  `WG_CMD_GET_DEVICE` (a dump), `WG_CMD_SET_DEVICE`, and the multicast event
  `WG_CMD_UNKNOWN_PEER` on group `auth` (not used here).
- Devices are made with rtnetlink, kind `amneziawg`; `newlink` reads no
  `IFLA_INFO_DATA`. A new device has MTU 1420.
- Both commands need `CAP_NET_ADMIN` (`GENL_UNS_ADMIN_PERM`), the dump too.
- A device is named by `WGDEVICE_A_IFINDEX` or `WGDEVICE_A_IFNAME`, exactly
  one of them (`lookup_interface`: both or neither is `EBADR`; a device of
  another kind is `EOPNOTSUPP`).
- The ops have no `GENL_DONT_VALIDATE_STRICT`, so strict validation applies:
  exact lengths for integers, `NLA_F_NESTED` on nests, no attribute past
  `WGDEVICE_A_DISABLE_COOKIES`. The kernel's WireGuard ends at
  `WGDEVICE_A_PEERS` and refuses anything after it.

## Ranges

`type.h`: a `u32` range is a `u64` `(hi << 32) | lo` (H1–H4); a `u16` range
is a `u32` `(hi << 16) | lo` (content padding addition, the five timers,
**and the peer's persistent keepalive**). The zero range means the module's
default.

The module never checks `lo <= hi`. It calls
`get_random_u32_inclusive(lo, hi)`, which with `lo > hi` returns values
outside the range. So:

- **A keepalive of 25 s is `25-25`**, sent as `(25 << 16) | 25`. Sent as a
  bare 25 (as WireGuard takes it) it is `lo = 25, hi = 0`, and every
  keepalive is at a random time. The kernel's WireGuard takes a `u16`.
- The crate's `U16Range`/`U32Range` cannot be made with `lo > hi`; one read
  from a device is checked before it is sent again.

## Junk: Jmin must not exceed Jmax

`send.c`, `wg_packet_send_handshake_initiation`: the buffer is
`kzalloc(jmax)` and each packet's size is
`get_random_u32_inclusive(jmin, jmax)`. With `jmin > jmax` the size can be
past the buffer, and `get_random_bytes` writes past its end: **a heap
overflow in the kernel from a configuration value**. The module does not
check it. `Obfuscation::validate` refuses it, and no update is sent without
it.

Junk is sent only while both `jc` and `jmax` are non-zero.

## Header protection

- `WGDEVICE_A_HEADER_PROTECTION_KEY`, exactly 32 bytes. While a device has
  it, or the message sets it, every S1–S4 has to be at least 12
  (`HEADER_PROTECTION_NONCE_SIZE`): `EINVAL` otherwise, both when S is set and
  when the key is.
- **It cannot be removed.** There is no attribute or flag that clears it.
  A device that is to lose it has to be deleted and made again; S cannot go
  below 12 on it either.
- The module reads S1–S4 before the key in the same message (the order of
  `wg_set_device`), so one message can raise S and set the key.

## H1–H4

Each H that is sent is checked for overlap against the other three, taking
the values of this message for those that are in it and the device's for
the rest. The crate always sends all four, so a swap of two in one message
is accepted.

## I1–I5

`junk.c`, `jp_spec_setup`:

- Tags `<b 0xHEX>`, `<c>`, `<t>`, `<r N>`, `<rc N>`, `<rd N>`; at most 65535
  bytes. The empty string sends nothing and is how one is cleared.
- **A refused template leaves the device in between**: the old packet is
  freed before the new text is parsed, and on failure the old text is kept.
  The device then sends no I-packet for it while a dump still shows the old
  text. `template::packet_size` checks a template first; it is stricter than
  the module (no text between tags, no unclosed last tag, no signs).

## No transaction

`wg_set_device` applies attributes in order and returns at the first error;
nothing before it is undone. The crate validates everything it can before
sending, and after a refusal the caller reads the device again. Updates
that are split into several messages (many peers) are each such a step.

## Errors

The module's refusals carry no extended-ACK text: the reason is only in
the kernel log, and only with dynamic debug on:

```sh
echo 'module amneziawg +p' > /sys/kernel/debug/dynamic_debug/control
```

So the crate states the reason itself for everything it checks
(`Error::Invalid`), and `EINVAL` from the kernel means a check it does not
mirror.

## The dump

- The device's attributes come in the first message only; peers continue
  over messages, and a peer whose allowed IPs did not fit is repeated at the
  start of the next with only its public key, flags and the rest of its
  allowed IPs (`get_peer`, `ctx->next_allowedip`). The crate joins them.
- `NLM_F_DUMP_INTR` (the device changed during the dump): read again.
- `WGPEER_A_RX_BYTES`/`TX_BYTES` are put with `nla_put_u64_64bit`, which may
  insert a pad attribute of type 0; it is skipped.
- `WGPEER_A_LAST_HANDSHAKE_TIME` is a `struct __kernel_timespec` (two `s64`);
  zero is "never".
- Every peer is reported with `WGPEER_F_HAS_ADVANCED_SECURITY` in its flags.
- I1–I5 are reported only once set; an unset one reads as "".
- With the module parameter `bogus_endpoints` set (`main.c`), peers'
  endpoints in a dump are made up from `127.0.0.0/8` and `ff80::/16`. The
  plugin's reported peer address is then meaningless.

## Byte order

Netlink is in the host's order, and OpenWrt runs on big-endian MIPS too:
everything is `to_ne_bytes`, except the port and flow label of a
`sockaddr_in`/`sockaddr_in6`, which are in network order.

## Odd things that do not matter here

- `timers.c:47` falls back to `REJECT_AFTER_TIME`, not `REKEY_AFTER_TIME`,
  when `rekey_after_time` is zero, in one of its two uses.
- `WGDEVICE_A_FWMARK` set to the same value still forgets every peer's
  cached source address.

## Verified

- Encoding and parsing: `cargo test -p awg-netlink` (byte layouts against the
  policies above, splitting and joining, refusals).
- WireGuard: `tests/live.rs` on a kernel's own module (ci.yml runs it on
  the runner's; it passed on Linux 7.0.12): create, set, a dump of 3000
  allowed IPs over several messages, `EEXIST`, `ENODEV`.
- AmneziaWG: `cargo xtask qemu-test` boots OpenWrt 25.12.6 armsr/armv8 in
  QEMU and loads the module built by `cargo xtask kmod`. The AmneziaWG
  round trip passes (header protection, H swapped in one message, back to
  the defaults, the module's own `EINVAL`), and awg-ctl's engine reaches
  `up` through a real handshake with every obfuscation on.
