**English** | [Русский](README.ru.md)

# SSTP GUI

A native, self-contained SSTP VPN client for macOS with a modern egui-based
GUI. No `pppd`, no `sstpc`, no Homebrew dependencies — the entire SSTP + PPP
protocol stack (TLS, HTTP handshake, SSTP framing, LCP/CHAP/IPCP negotiation,
MPPE keys, SSTP's crypto-bind) is implemented from scratch in Rust and
compiled straight into a single ~15MB `.app`.

## Why

macOS has no built-in SSTP support, and the usual workaround —
[`sstp-client`](https://github.com/eivnaes/sstp-client) driving Apple's
ancient, unmaintained `pppd` — is fragile in practice: `pppd` doesn't
reliably tear down its interface or route changes when killed, its logging
is effectively invisible, and enabling `defaultroute` to actually route
traffic through the tunnel can create a routing loop that kills the
control connection the moment it takes effect. This project replaces that
whole dependency chain with one Rust binary that owns the TLS session, the
SSTP control protocol, PPP negotiation, and the macOS network interface
directly — no external process to crash, no closed-source route logic to
fight.

## Requirements

- macOS 11+
- Rust (stable, edition 2024)
- An SSTP VPN server (e.g. Windows RRAS, or [accel-ppp](https://github.com/accel-ppp/accel-ppp))

## Building

```sh
./build.sh
```

This builds the release binary, generates the app icon if needed, and
assembles `SSTP GUI.app` (ad-hoc code-signed) in the repo root. Open it
directly or move it to `/Applications`.

## Architecture

- **`sstp-proto/`** — the protocol engine: TLS + HTTP handshake, binary SSTP
  framing, PPP (LCP/CHAP-MSCHAPv2/IPCP), MPPE key derivation, SSTP's
  compound-MAC crypto-bind, and the macOS `utun` interface. Has no GUI
  dependencies, so it builds and its ~70 unit tests run in seconds. Almost
  every wire-format detail is cross-checked against RFC 1661/1332/1877/1994/
  2759/3079 and, where the RFCs are ambiguous, against a captured real-world
  negotiation.
- **`src/`** — the egui GUI, profile/Keychain management, and the
  root-privilege worker process. Creating a `utun` interface and changing
  routes needs root for the entire lifetime of the connection (not just a
  one-shot command), so the same binary re-invokes itself as
  `sstp-gui --vpn-worker <server> <username>` via `osascript`'s
  `do shell script ... with administrator privileges`, and coordinates with
  the unprivileged GUI process through small files under
  `~/Library/Application Support/sstp-gui/` (there's no realtime IPC channel
  back to the caller of `do shell script`).

## Safety notes

Before pointing the default route at the tunnel interface, the worker adds a
host route to the VPN server's own IP via the original gateway, so the
tunnel's own TLS connection can't get routed into itself. If the worker
process dies unexpectedly, the GUI detects the broken default route and
restores the pre-VPN gateway automatically.

## License

MIT — see [LICENSE](LICENSE).
