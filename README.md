# pktscope

A Wireshark-style packet analyzer for the terminal, built as a
[yeet](https://yeet.cx) script: a reactive JSX TUI fed by a TCX (clsact)
eBPF tap, bundled with esbuild and driven by one `make`.

```sh
make           # compile the BPF tap + bundle the JS
yeet run .     # interface picker (needs root for BPF)
yeet run . -- --iface eth0 --port 443 --proto tcp
```

Three panes, Wireshark-shaped:

- **Packet list** — live rows colored by what the payload was identified
  as: TLS records (with SNI), HTTP/1 (request/status + headers), HTTP/2
  preface + frames, DNS queries/responses, ARP. Columns drop by priority
  as the terminal narrows.
- **Protocol detail tree** — folding sections (Frame / Ethernet / IP /
  TCP·UDP·ARP / Payload); every field carries the byte range it decodes.
- **Hex pane** — every byte colored by the section it belongs to
  (ethernet / IP / L4 / payload), with the field selected in the tree
  highlighted byte-for-byte.

## Capture

The tap (`src/bpf/pktscope.bpf.c`) attaches TCX ingress + egress hooks and
streams full frames (up to 1536 B) to a ring buffer. Where the snap starts
is per-interface:

- **Ethernet-framed devices** (incl. loopback, veth, bridges, tap) capture
  from the MAC header — link-level frames like ARP come through and are
  fully decoded.
- **Raw-IP tunnel devices** (`tunl*`/`ipip`/`gre`/`tun`/`wg`) capture from
  the network header, where tcpdump-era assumptions about an Ethernet
  header break.

The program is a passive observer: it always returns `TCX_NEXT`, never
dropping or altering traffic. Kernel-side port/proto filters (from
`--port` / `--proto`) keep uninteresting traffic out of the ring entirely.

## Keys & mouse

- **Picker**: `↑↓` select · `⏎`/`→` capture
- **List**: `↑↓`/`jk` packet · `→`/`⇥` fields pane · `f` follow tail ·
  `p` pause · `/` filter · `c` clear · `1·2·3` toggle panes · `z` zoom ·
  `+`/`-` resize · `←`/`esc` back · `q` quit
- **Fields**: `↑↓` field · `→` open/descend · `←` fold/back · `⏎` toggle fold
- **Mouse**: the wheel scrolls the pane under the cursor (including the
  bytes pane), click selects, dragging a pane divider resizes it.

## Display filter

`/` opens a filter. Space-separated terms AND together; `!` negates;
anything unrecognized is a substring match over the packet's decoded text
and printable payload — so a bare `ClaudeBot` or `10.0.0.7` just works.

```
tls http1 http2 dns text arp     identified kind / frame type
tcp udp icmp                     l4 protocol
port 443  host 10.0.0.1          endpoints (src/dst work too)
sni example.com  ua ClaudeBot    decoded fields
syn rst fin ack  rx tx  data     tcp flags, direction, has-payload
len>500  !ack                    length compare, negation
```

## Layout

```
Makefile                build frontend — clang/bpftool + esbuild
build/                  toolchain resolution, BPF rules, kernel-matrix CI
src/main.jsx            entry — composition root: input, layout, mount
src/probes/tap.js       loads bin/probe.bpf.o, arms the scope, streams packets
src/probes/capture.js   capture session state: packet ring + UI signals
src/probes/ifaces.js    interface inventory for the picker (kind, rates, L2)
src/components/*.jsx    pure UI: list, detail tree, hex pane, picker, chrome
src/lib/proto.js        pure dissection: ethernet/ARP/IP/TCP/UDP + payload ID
src/lib/filter.js       display-filter compiler
src/lib/format.js       palette + table/format helpers
src/bpf/pktscope.bpf.c  the TCX tap
```

The JS is layered: `probes/` is the only BPF-aware code (it owns the
object and exposes plain signals), `components/` is pure presentation, and
`lib/` is pure parsing/formatting. `@/` (source root) and `#/` (project
root) are bundle-time aliases esbuild resolves via tsconfig `paths`; the
BPF object is located at runtime with `import.meta.dirname`.

## Build

`make` runs two independent compilers: **clang + bpftool** compile
`src/bpf/pktscope.bpf.c` into the loadable object `bin/probe.bpf.o`, and
**esbuild** bundles `src/main.jsx` into `src/index.jsx`, leaving `yeet:*`
builtins external. clang, bpftool, and esbuild come from a static,
checksum-pinned toolchain (`build/toolchain.lock`) — the build needs no
system C toolchain and no node/npm.

## Testing across kernels

`make veristat` loads the object with veristat on **your** kernel (needs
`sudo`) — a quick check that every program passes the verifier, plus
per-program complexity.

A program that loads on your laptop can still be rejected by an older
kernel's verifier. `.github/workflows/kernel-matrix.yml` builds the
object, boots each kernel in its matrix in a VM
([cilium's little-vm-helper](https://github.com/cilium/little-vm-helper)),
and fails if any verifier rejects it. Run the same matrix locally
(Linux + KVM) with `make veristat-matrix KERNELS="6.6-main bpf-next-main"`.

## Prerequisites

- Linux with `CONFIG_DEBUG_INFO_BTF` (for `vmlinux.h` generation and
  CO-RE-free BTF loading)
- root (or CAP_BPF + CAP_NET_ADMIN) to load and attach the tap
