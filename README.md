<!-- markdownlint-disable MD033 MD041 -->
# `pktscope`

> **Wireshark's three panes, in your terminal, over SSH.**

<p align="center">
  <a href="#requirements"><img alt="Linux: kernel 6.6+ with BTF and TCX" src="https://img.shields.io/badge/platform-Linux-informational"></a>
  <a href="https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=pktscope&utm_content=badge"><img alt="Built with yeet, a JS runtime for eBPF" src="https://img.shields.io/badge/built%20with-yeet%20%2B%20eBPF-blueviolet"></a>
  <a href="#how-it-works"><img alt="Captures full frames at the TCX ingress and egress hooks" src="https://img.shields.io/badge/capture-TCX%20ingress%20%2B%20egress-blue"></a>
  <a href="#license"><img alt="Dual BSD/GPL licensed BPF program" src="https://img.shields.io/badge/license-Dual%20BSD%2FGPL-green"></a>
  <a href="https://discord.gg/JxVseaAVAU"><img alt="Discuss pktscope on Discord" src="https://img.shields.io/badge/chat-Discord-5865F2"></a>
</p>

<!-- Hero GIF not captured yet. Record a session (interface picker → capture → arrow into a TLS
     packet → watch the hex pane highlight the SNI bytes) and drop it at assets/pktscope.gif.
<p align="center">
  <img width="820" alt="pktscope: packet list, protocol detail tree, and section-colored hex" src="assets/pktscope.gif">
</p>
-->

**`pktscope` is an eBPF packet analyzer for the Linux terminal: it captures full frames at the TCX hooks and gives you Wireshark's packet list, folding protocol tree, and byte-highlighted hex.**

You pick an interface, and every frame crossing it streams into a live list colored by what the payload turned out to be: TLS records with the SNI pulled out of the ClientHello, HTTP/1 request lines and headers, the HTTP/2 preface and its frames, DNS questions and answers, ARP. Arrow into any packet and the detail tree unfolds it section by section (Frame / Ethernet / IP / TCP·UDP·ARP / Payload), and every field you land on lights up exactly the bytes it decodes in the hex pane below.

The tool you would otherwise reach for is `tcpdump -w`, an `scp`, and Wireshark on your laptop. That round trip costs you the live view, and it breaks entirely on the interfaces where you most need it: `tcpdump` on a raw-IP tunnel device (`tunl0`, `ipip`, `gre`, `wg`) still assumes an Ethernet header that the device never puts there. `pktscope` decides where the snap starts per interface, so a tunnel decodes as cleanly as `eth0`.

> [!TIP]
> **The capture anchor is per-interface, decided in the kernel.** Userspace writes each Ethernet-framed device's link header length into a BPF hash map, and the tap reads frames from the MAC header on those and from the network header on everything else. That one map is why the same program handles `eth0`, a veth pair, and `tunl0` without a `-y` flag or a guess about link type.

## Questions this tool answers

**How do I inspect packets on a box where I can't install Wireshark, or anything else?**
`curl -fsSL https://yeet.cx | sh`, then `yeet run gh:yeet-src/pktscope`. That fetches and builds the repo for you, pulling a static, checksum-pinned clang and esbuild into a per-machine cache, so there is no system C toolchain, no Node, and no `libpcap` to satisfy. See [Quick start](#quick-start).

**How can I read a packet capture live instead of writing a pcap and opening it somewhere else?**
That round trip is the workflow `pktscope` replaces. Frames stream from the ring buffer into the list as they cross the interface, and `p` pauses the feed so you can walk what you already have without losing what arrives next. See [What you're looking at](#what-youre-looking-at).

**Why does `tcpdump` produce garbage on my `tunl0` / `ipip` / `gre` / WireGuard interface?**
Because those devices hand you a bare IP packet, and a decoder that assumes a 14-byte Ethernet header parses the IP header as MAC addresses. `pktscope` marks Ethernet-framed devices in a BPF hash map and anchors the capture at the network header for everything else. See [Capture anchoring](#capture-anchoring).

**How do I confirm which TLS server name a process is actually connecting to, without decrypting anything?**
The SNI travels in cleartext inside the ClientHello, before any key exchange. `pktscope` walks the ClientHello extensions, extracts the server name, puts it in the list row, and highlights the exact bytes it came from. Filter for it with `sni example.com`. See [Payload identification](#payload-identification).

**Can I filter packets the way I would in Wireshark, without learning a new expression language?**
`/` opens a display filter where space-separated terms AND together and `!` negates: `tls port 443 !ack`. Anything the compiler does not recognize becomes a substring match over the decoded fields and the printable payload, so a bare `ClaudeBot` or `10.0.0.7` works and nothing you type is ever a syntax error. See [Display filter](#display-filter).

**Is this a replacement for Wireshark?**
No. Wireshark has hundreds of protocol dissectors, TCP stream reassembly, follow-stream, decryption with a keylog file, saved captures, and statistics. `pktscope` dissects Ethernet, ARP, IPv4, IPv6, TCP, UDP, and identifies five payload kinds, one packet at a time, with no reassembly and no file output. What it has instead is that it is already on the host, it runs over SSH in a terminal, and it does not care what link type the interface is. For a full analysis session, capture with `tcpdump -w` and open the file in Wireshark.

**When should I use this instead of `tcpdump`, `tshark`, or `termshark`?**
Use `tcpdump` when you need a pcap to keep, to share, or to feed something else; `pktscope` writes no files. Use `tshark` or `termshark` when you need real dissector coverage or stream reassembly. Reach for `pktscope` when you want to *look* at what is crossing an interface right now, in a terminal, with the bytes and the field that decodes them on screen together, and especially when the interface is a tunnel.

**Can I see the contents of an HTTPS request?**
Not the plaintext. TLS payload is ciphertext at the capture layer, so the payload section says so and shows you the record layer instead: handshake type, record boundaries, the SNI. Reading decrypted request bodies needs a uprobe on `SSL_write`/`SSL_read`, which is a different tool: see [`wssnoop`](https://github.com/yeet-src/wssnoop) for the OpenSSL-boundary approach, or [`redissnoop`](https://github.com/yeet-src/redissnoop) for how the same trick reads TLS Redis traffic.

**How do I see gRPC calls or HTTP/2 request headers?**
`pktscope` identifies HTTP/2 frames by type and stream, but HPACK-compressed headers stay compressed: it labels a HEADERS frame `hpack-coded headers` rather than pretending to decode it. For readable gRPC method names and protobuf fields, use [`grpcsnoop`](https://github.com/yeet-src/grpcsnoop), which reassembles the stream and unwinds all three layers.

**How can I check what is on the wire between two containers on the same host?**
Pick the veth interface for the container, or the bridge (`docker0`, `br-*`). Those are Ethernet-framed, so ARP and link-level frames decode in full. For a ranked, per-container view of HTTP rather than a per-packet one, [`container-traffic`](https://github.com/yeet-src/container-traffic) is the better fit.

## Contents

**Run it** — [Quick start](#quick-start) · [Have an agent set it up](#have-an-agent-set-it-up) · [Reading it without a TTY](#reading-it-without-a-tty)
**Understand it** — [A 30-second primer on where a packet gets captured](#a-30-second-primer-on-where-a-packet-gets-captured) · [What you're looking at](#what-youre-looking-at) · [Navigation](#navigation) · [Display filter](#display-filter) · [How it works](#how-it-works)
**Reference** — [Requirements](#requirements) · [What it can't see](#what-it-cant-see) · [FAQ](#faq) · [License](#license)
**Contribute** — [Building from source](#building-from-source) · [Testing across kernels](#testing-across-kernels)

Up top: [Questions this tool answers](#questions-this-tool-answers).

## Quick start

```sh
curl -fsSL https://yeet.cx | sh
yeet run gh:yeet-src/pktscope      # interface picker, then capture on the one you choose
```

[Manual install guide](https://yeet.cx/docs/install/manual-installation?utm_source=github&utm_medium=readme&utm_campaign=pktscope) | Linux only

Nothing to clone and nothing to build by hand: `yeet run` fetches the repo and runs `make` itself, which compiles the BPF object and bundles the JS from a pinned static toolchain. Pin a branch or tag with `@`, as in `gh:yeet-src/pktscope@main`.

With no flags you land on the interface picker: every interface on the host with its state, kind, first address, and live packet rates, refreshed once a second. `↑↓` to choose, `⏎` or `→` to start capturing.

Skip the picker by naming an interface, and narrow the capture in the kernel with `--port` and `--proto`:

```sh
yeet run gh:yeet-src/pktscope -- --iface eth0                     # capture immediately
yeet run gh:yeet-src/pktscope -- --iface tunl0                    # a raw-IP tunnel, decoded correctly
yeet run gh:yeet-src/pktscope -- --iface lo                       # local service-to-service traffic
yeet run gh:yeet-src/pktscope -- --iface eth0 --port 443 --proto tcp  # only TCP/443, filtered in-kernel
yeet run gh:yeet-src/pktscope -- --iface eth0,veth1234            # two interfaces at once
```

Working from a clone instead? `make` then `yeet run .` does the same thing; see [Building from source](#building-from-source).

| flag | what it does |
| --- | --- |
| `--iface` / `-i` | Interface name or ifindex, comma-separated for several. Skips the picker. |
| `--port` | Kernel-side port filter, matching either endpoint. Non-matching packets never enter the ring buffer, so this is the cheap way to narrow a busy interface. Only meaningful for TCP and UDP; setting it drops non-IP frames like ARP. |
| `--proto` | `tcp` or `udp`. Also a kernel-side filter, and also drops non-IP frames. |

Flags go after `--` so the runtime hands them to the script rather than eating them itself; getting that wrong is the usual first-run surprise. `pktscope` runs until you press `q` or `Ctrl-C`, reflows on terminal resize, and needs a real TTY, so don't pipe or redirect it. There is no `sudo` here: the yeet daemon owns the privileged BPF load.

## Have an agent set it up

Paste this to a coding agent with shell access on the target Linux host:

```text
Set up and verify pktscope, an eBPF terminal packet analyzer, on this host.

1. Install the yeet daemon if it isn't present: curl -fsSL https://yeet.cx | sh
2. Generate traffic to look at, since an idle interface and a broken capture
   look identical on screen. In one shell: `curl -s https://example.com >
   /dev/null` in a loop, or `dig example.com` for DNS.
3. Confirm it captures. pktscope is a full-screen TUI, so run it in a real
   terminal:
   `yeet run gh:yeet-src/pktscope -- --iface <the interface carrying that traffic>`
   Success is rows appearing in the packet list with a protocol in the `proto`
   column and a decoded summary in `info` (a TLS handshake with an SNI, an HTTP
   request line, a DNS question). Press `q` to quit.
4. Report the kernel version (`uname -r`), whether CONFIG_DEBUG_INFO_BTF is
   enabled, and the exact error text if the BPF load failed.

If you need to modify the script rather than just run it, clone
https://github.com/yeet-src/pktscope, read AGENTS.md first (it is the API
contract for the yeet TUI runtime and the gotcha list), then `make` and
`yeet run .` from the clone.

Trap to expect: TCX attach needs Linux 6.6 or newer. On an older kernel the load
fails at attach time, not at compile time, so "it compiled" is not the same as
"it works". Report the attach error rather than assuming the build succeeded.
```

Prefer to drive it yourself? [Quick start](#quick-start) is the same three commands.

## A 30-second primer on where a packet gets captured

A packet on the wire is a stack of headers, each one saying what the next is. On an Ethernet link that stack starts with a 14-byte **MAC header**: destination address, source address, and a 2-byte **ethertype** naming what follows (`0x0800` IPv4, `0x86dd` IPv6, `0x0806` ARP). Then the **network header** (IP), then the **transport header** (TCP or UDP), then whatever the application put in the payload.

The catch is that not every interface has that first layer. A raw-IP tunnel device (`tunl0`, `ipip`, `gre`, a WireGuard or `tun` VPN) hands the stack a bare IP packet with no MAC header at all, and a decoder that assumes 14 bytes of Ethernet will read the IP version and TTL as the tail of a MAC address. This is why a tool has to know the interface's link type before it can parse a single byte, and why getting it wrong produces confident nonsense rather than an error.

`pktscope` captures at the **TCX hooks**, the kernel's modern traffic-control attach point, one program on ingress and one on egress. At that layer the whole frame is available, including the link header when there is one, which is what makes ARP visible and what makes the per-interface anchor decision possible in the first place. It also means the plaintext ceiling is the wire: TLS payload arrives encrypted, and encrypted is how you see it.

## What you're looking at

Three panes, top to bottom: the packet list, the protocol detail tree, and the hex dump.

```
 ◉ pktscope  ▏ eth0 · port 443 tcp  ▏ 1 1284 pkts ▼701 ▲583 · 412.6 kB  ▏ tls 96 · http/1 18 · dns 7  ▏ ● live
     #      time   source                   destination           proto    len  info
   1281     4.118 ▼ 93.184.216.34:443     → 10.0.0.7:52918          tcp   1494  [PSH,ACK] 1440 B
   1282     4.118 ▼ 93.184.216.34:443     → 10.0.0.7:52918          tcp    712  TLS 1.3 ApplicationData · 654 B
   1283     4.121 ▲ 10.0.0.7:52918        → 93.184.216.34:443       tcp     66  [ACK] seq=2118374401
   1284     4.196 ▲ 10.0.0.7:53004        → 93.184.216.34:443       tcp    583  TLS 1.3 Handshake ClientHello · sni=example.com
 2 fields ── TCP · 53004 → 443 [PSH,ACK]
   ▾ Frame · 583 B on wire · 583 B captured
       direction    egress (tx)
       interface    ifindex 2
   ▸ Ethernet · 3c:22:fb:1a:9e:04 → 00:1b:21:0a:4c:7f
   ▸ IPv4 · 10.0.0.7 → 93.184.216.34
   ▾ TCP · 53004 → 443 [PSH,ACK]
       src port     53004
       dst port     443
       seq          1904772331
       flags        PSH,ACK
   ▾ Payload · 517 B · tls
       record       Handshake ClientHello · 512 B
       sni          example.com
 3 bytes
   0x0040  16 03 01 02 00 01 00 01  fc 03 03 9d 5f 2a b1 c4   ............_*..
   0x0050  7e 33 08 ff 21 6b 0d 4a  c9 88 41 e7 05 3b 62 f0   ~3..!k.J..A..;b.
   0x0060  00 00 0e 00 00 0b 65 78  61 6d 70 6c 65 2e 63 6f   ......example.co
   0x0070  6d 00 17 00 00 ff 01 00  01 00 00 0a 00 08 00 06   m...............
 ↑↓ packet  → fields  ← interfaces  p pause  f follow  / filter  c clear  z zoom
```

The top rail carries the interface being captured, the kernel-side scope if you set one, running counters (total, ingress, egress, payload bytes), a tally per identified payload kind, and the capture state (`● live`, `● live ↧` when you have scrolled off the tail, `⏸ paused`, `⏹ stopped`). When a filter is applied it echoes the terms *as understood* along with how many packets pass, which is how you tell a too-tight filter from a quiet interface. The bottom rail is a key-hint rail that follows whichever pane has focus.

Packet list columns:

| column | meaning |
| --- | --- |
| `#` | Capture sequence number, counted from the start of this session, not a kernel counter. |
| `time` | Seconds since the first packet of the capture, to milliseconds. |
| (arrow) | `▼` ingress, `▲` egress, colored so direction reads at a glance. |
| `source` / `destination` | `address:port` for TCP and UDP; the MAC address for link-level frames with no ports. |
| `proto` | The L4 protocol name for IP packets (`tcp`, `udp`, `icmp`, `gre`, …), or the ethertype for non-IP frames (`arp`, `lldp`, …). |
| `len` | Full frame length on the wire, which can exceed the bytes captured. |
| `info` | What the payload was identified as, rendered: a TLS record with its handshake type and SNI, an HTTP request line, a DNS question, or the TCP flags and payload size when nothing identified. |

Rows are colored by identified payload kind, and a TCP `RST` recolors the row regardless of kind so a reset stands out. Columns drop by priority as the terminal narrows: `len` goes first, then `time` and `#`, then the `→` separator, then `proto`, leaving source, destination, and info to share the width.

The **fields pane** is the detail tree. Sections fold and unfold, and every row carries the byte range it decodes. The **bytes pane** colors each byte by the section it belongs to (Ethernet, IP header, L4 header, payload) and, while the fields pane has focus, highlights exactly the range the selected field covers. Selecting `sni` in the tree lights up the eleven bytes spelling `example.com` in the dump, which is the whole point of the pane.

### Payload identification

The payload is identified by a chain of five classifiers, tried in that order, on the bytes after the L4 header of a single packet:

| kind | what it recognizes | what it pulls out |
| --- | --- | --- |
| `dns` | UDP with port 53 on either end | Query or response, question type (`A`, `AAAA`, `HTTPS`, …), the queried name, answer count |
| `tls` | A TLS record header (content type 20-23, major version 3) | Up to eight records with boundaries and lengths, handshake message type, the SNI from a ClientHello |
| `http/1` | A request line with one of nine methods, or an `HTTP/1.x` status line | The start line plus up to 24 headers, each individually selectable, and the captured body length |
| `http/2` | The `PRI * HTTP/2.0` preface, or plausible frame headers | Up to ten frames by type, stream id, length, and end-of-stream flags |
| `text` | Payload that is at least 85% printable in its first 72 bytes | The first line, up to 64 characters |

ARP is decoded separately, since it has no IP header to hang a payload off: opcode, sender and target hardware and protocol addresses, and a summary in the list row (`who has 10.0.0.1? tell 10.0.0.7`).

## Navigation

| key | action |
| --- | --- |
| `↑↓` / `jk` | Move the selection in the focused pane |
| `→` / `⇥` | Drill in: pick an interface, step into the fields pane, open a folded section, descend to its fields |
| `←` / `esc` | Climb back out: field to section, fold an open section, fields pane to the list, list to the picker |
| `⏎` | Start capturing (picker), or toggle a fold (fields pane) |
| `PageUp` / `PageDown` | Page the focused pane |
| `g` / `G` | Jump to the first or last row |
| `f` | Follow the tail again |
| `p` | Pause the feed; packets already captured stay browsable |
| `/` | Open the display filter |
| `c` | Clear the capture and the counters |
| `1` `2` `3` | Toggle the packets, fields, and bytes panes |
| `z` | Zoom the focused pane to the whole body |
| `+` `-` | Trade rows between the focused pane and its neighbour |
| `q` / `Ctrl-C` | Quit |

`←` and `→` are drill-down everywhere, which is the one thing worth internalizing: `→` always goes deeper (interface, then packet, then section, then field) and `←` always comes back out along the same path. Follow mode re-engages only when you are parked on the literal newest packet, so the last row of a filtered list does not silently pin you to the tail.

The mouse works too: the wheel scrolls whichever pane is under the cursor (including the bytes pane), a click selects the row it lands on, and dragging a pane divider resizes just the two panes it separates, tmux-style.

## Display filter

`/` opens a filter. Space-separated terms AND together, `!` or `-` negates one, and the rail echoes what was understood alongside the match count.

```
tls http1 http2 dns text arp     identified kind / frame type
tcp udp icmp icmp6 gre esp sctp  l4 protocol
port 443  host 10.0.0.1          endpoints (src and dst work too)
sni example.com  ua ClaudeBot    decoded fields
syn rst fin ack psh urg          tcp flags
rx  tx  data                     direction, carries payload
len>500  len<=64                 length comparison (>, <, >=, <=, =)
!ack  -syn                       negation
```

Spacing and punctuation are normalized before parsing, so `port 443`, `port:443`, and `port=443` all mean the same thing, as do `len>500` and `len > 500`.

Anything not recognized as a term becomes a substring match over the packet's searchable text: both endpoints, the protocol name, the TCP flags, the identified kind, every decoded field label and value, and the printable run of the payload. So `ClaudeBot` finds the requests carrying that user agent, `example.com` finds both the DNS question and the TLS SNI, and nothing you type is ever an error. This is filtering the packets already in the ring, so it is retroactive: applying a filter re-selects what you captured, and `--port` / `--proto` are the ones that decide what gets captured at all.

## How it works

The JS is layered, and the layering is enforced by convention: `src/probes/` is the only code that touches `yeet:bpf`, `src/components/` is pure presentation that reads signals, and `src/lib/` is pure parsing and formatting with no state at all. `@/` (source root) and `#/` (project root) are bundle-time aliases that esbuild resolves through tsconfig `paths`; the runtime resolver knows nothing about them, which is why the BPF object is located with `import.meta.dirname`.

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

### The BPF side

Two programs, one object, both attached per interface with a TCX link:

| program | hook | what it captures |
| --- | --- | --- |
| `tap_ingress` | `tcx/ingress` | Every frame arriving on the interface |
| `tap_egress` | `tcx/egress` | Every frame leaving the interface |

Both call the same `tap()` body and both return `TCX_NEXT` unconditionally: the program is a passive observer that never drops, delays, or alters a packet. Three maps:

| map | type | what it carries |
| --- | --- | --- |
| `scope` | `ARRAY`, one entry | The capture scope written from JS: `on`, `port`, `proto`. `on == 0` means attached but streaming nothing. |
| `l2map` | `HASH`, 64 entries | ifindex to link header length. An entry (14) means Ethernet framing; a missing entry means the device hands over raw IP. |
| `events` | `RINGBUF`, 4 MiB | Captured packets, as a `scope_pkt` struct read on the JS side through its BTF name. |

The kernel-side filter is what keeps this cheap on a busy interface. `--port` and `--proto` land in `scope`, and a packet that does not match is dropped before any ring-buffer reservation, so the cost scales with matched packets rather than total traffic. The snap length is 1536 bytes, measured from the first captured byte, which fits a full untagged Ethernet MTU frame with room to spare.

Each event carries the packet bytes plus the offsets that make the hex pane's coloring possible: `l3off`, `l4off`, and `payoff`, the boundaries of the link, network, and transport headers within the captured buffer. The kernel computes them because it is the only layer that knows the anchor; JS never has to guess where a header started.

#### Capture anchoring

Userspace populates `l2map` before arming the tap, deriving the link header length from the interface name and kind: 14 for Ethernet devices, veth pairs, bridges, loopback, and `tap`/`gretap` devices, and 0 for raw-IP tunnels (`tunl*`, `ipip`, `sit`, `gre`, `ip6tnl`) and `tun`/`wg` VPN devices. The program then reads each frame with `bpf_skb_load_bytes_relative`, anchored at `BPF_HDR_START_MAC` when there is a link header and `BPF_HDR_START_NET` when there is not.

On Ethernet framing the ethertype gates the IP parse, so an ARP body cannot masquerade as IPv4 just because its first nibble happens to be 4. Non-IP frames come through with `ver == 0` and identify themselves by ethertype alone, which is how ARP reaches the detail tree fully decoded.

<details>
<summary>Two verifier fights worth knowing about, if you write BPF</summary>

**Zeroing the event.** A whole-struct `__builtin_memset` over a 1536-byte buffer is too large for clang to expand on the BPF target, so the fixed header is zeroed with the builtin and the capture buffer with an 8-byte-stride loop. The stores are `volatile` specifically to stop clang's idiom recognizer from folding that loop back into the `memset` call it just refused to expand.

**Proving the copy length.** The frame is pulled linear with `bpf_skb_pull_data` first, because loopback and GSO skbs keep the payload paged and the relative loader only reaches the linear header area (it returns `EFAULT` past it). Then the copy length has to be proven in `[1, CAP]` on the exact register handed to the helper, which took three tries across kernel generations. `barrier_var` makes the value opaque *before* the clamp, or clang either elides the clamp as provably dead or fuses the range check into a decremented copy, and the branch refinement then lands on a different register than the call argument. A second `barrier_var` hides the clamp from clang again, because knowing `copy <= CAP` it would fold the signed compare back into `!= 0`. And the lower bound is a *signed* compare on purpose: verifiers before 6.8 do not lift `umin` on a `!= 0` branch, but have always refined `JSGT`.

Both are in `src/bpf/pktscope.bpf.c` with the reasoning in comments, and both are why [Testing across kernels](#testing-across-kernels) exists.

</details>

### The JS side

| file | responsibility |
| --- | --- |
| `probes/tap.js` | Loads the object, binds the three maps, attaches both programs to the chosen ifindexes, writes `l2map`, subscribes to the ring buffer, then arms `scope` last so nothing streams before a subscriber is listening. Normalizes each event into a plain packet object. |
| `probes/capture.js` | Owns the packet ring (4000 packets, trimmed 512 at a time) and the session lifecycle, and publishes a `tick` signal on a 150 ms window rather than per packet. |
| `probes/ifaces.js` | Polls the yeet system graph once a second for interfaces, addresses, and packet rates, and classifies each device's kind and link header length. |
| `lib/proto.js` | All dissection: the section tree with a byte range on every field, the five payload classifiers, the list-row summary, and the searchable text a bare filter word matches against. |
| `lib/filter.js` | Compiles a filter string into a predicate plus the list of terms it understood, for the rail. |
| `components/*.jsx` | Pure presentation. One column spec drives both the header and every row of a table, so they cannot drift out of alignment, and columns drop by priority as the terminal narrows. |

The division of labor is deliberate: the kernel does the anchoring, the coarse port/proto filter, and the offsets, and nothing else. Every protocol decision (which classifier matched, what a field means, which bytes to highlight) happens in userspace, where being wrong costs a wrong row rather than a verifier rejection. That is also why the dissectors live in a module with no imports from `probes/`: they are pure functions from a captured packet to structure, testable without a kernel.

A busy interface fires the ring-buffer callback thousands of times a second, so packets accumulate in a plain array and a 150 ms timer publishes a `tick` the UI subscribes to. One repaint per frame, not one per packet.

### Why TCX, not a raw socket or libpcap

A raw `AF_PACKET` socket, which is what `libpcap` and therefore `tcpdump` use, copies every frame to userspace and filters there or with a classic BPF program attached to the socket. It works, and it is the reason `tcpdump` runs everywhere, but the filtering happens after the copy or inside a much older instruction set, and the link type is something the tool has to look up and then trust.

The TCX hooks sit in the kernel's traffic-control path, where the full frame is present, the modern BPF instruction set and maps are available, and the attach is per-interface and multi-program (so `pktscope` attaching does not disturb anything else already hooked there). That is what buys the two things this tool is built around: a port/proto filter that runs before any copy, and a per-interface capture anchor that the kernel reads out of a map instead of the tool assuming a link type.

## Reading it without a TTY

There is no headless mode. `pktscope` is a full-screen TUI: it needs a real terminal, it repaints in place, and it has no `--json` output, no one-shot mode, and no `import.meta.main` self-test on its probe modules.

For an agent or a CI job that needs packet data as text rather than as a screen, the place to add one is `src/probes/tap.js`, whose `startScope()` already takes an `onPacket` callback and hands it a plain object. A dozen lines under `import.meta.main` that attach, print JSON for a few seconds, and exit would make `yeet run src/probes/tap.js` the headless path (mind that `@/` is bundle-time only, so a standalone module has to reach its siblings by relative path). Until that exists, verification means running the TUI in a terminal and looking at it, which is what [Have an agent set it up](#have-an-agent-set-it-up) asks for.

## Building from source

```sh
make            # everything: BPF object + JS bundle
make bpf        # just src/bpf/*.bpf.c → bin/probe.bpf.o
make bundle     # just src/main.jsx → src/index.jsx
make veristat   # load the object and check this kernel's verifier accepts it
make clangd     # write a local .clangd pointing at the resolved toolchain
make clean      # remove build artifacts
```

`make` runs two independent compilers that know nothing about each other. clang and bpftool compile `src/bpf/pktscope.bpf.c` into the loadable object `bin/probe.bpf.o`; esbuild bundles `src/main.jsx` into `src/index.jsx`, leaving `yeet:*` builtins external and never touching the compiled object, which JS locates by path at runtime. Both tools come from a static, checksum-pinned toolchain (`build/toolchain.lock`) fetched into a per-machine cache, so the build needs no system C toolchain and no Node or npm.

`src/index.jsx` is the built bundle and the entry `yeet run` prefers once it exists, and `bin/*.bpf.o` is the compiled object; both are build artifacts rather than sources. `yeet run` invokes `make` itself when running the project from a trusted remote source, so the default goal always leaves the project runnable.

## Testing across kernels

A BPF program that loads on your laptop can still be rejected by an older kernel's verifier, and this program's copy-length proof is exactly the kind that changes behavior between kernel generations.

`make veristat` loads the object with the vendored static `veristat` on **your** kernel and reports a verdict plus per-program complexity. Loading BPF needs privileges, so this one does take `sudo`.

`.github/workflows/kernel-matrix.yml` runs the same check across 6.1, 6.6, 6.12, and `bpf-next` on every push and pull request, booting each kernel in a VM with [cilium's little-vm-helper](https://github.com/cilium/little-vm-helper) and failing if any verifier rejects any program. It reads `veristat`'s verdict column rather than its exit code, because `veristat` exits 0 even when a program fails to load. Run the same matrix locally on Linux with KVM:

```sh
make veristat-matrix KERNELS="6.6-main bpf-next-main"
```

## Requirements

> [!IMPORTANT]
> Linux with **BTF** (`CONFIG_DEBUG_INFO_BTF=y`), needed to generate `vmlinux.h` and to read the `scope_pkt` struct out of the ring buffer by its BTF name. Default on current Arch, Fedora, Ubuntu 24.04+, and Debian 12+.
>
> Kernel **6.6 or newer** for TCX links, which is the attach point both programs use. CI verifies down to 6.1, but that covers the verifier accepting the programs, not TCX being available to attach them.
>
> The yeet daemon, which handles the privileged BPF load. `curl -fsSL https://yeet.cx | sh` installs it.

## What it can't see

> [!NOTE]
> `pktscope` observes. It tells you what crossed the interface; it never drops, holds, delays, or modifies a packet, and it writes no capture files.

- **TLS payload is ciphertext.** You get the record layer (handshake type, record boundaries, lengths) and the SNI from a ClientHello, because those are cleartext by design. Application data is encrypted, and the payload section says so rather than showing you noise. Plaintext needs a uprobe at the TLS library boundary: [`wssnoop`](https://github.com/yeet-src/wssnoop) and [`redissnoop`](https://github.com/yeet-src/redissnoop) take that approach.
- **No TCP reassembly.** Every packet is dissected on its own. A TLS record or an HTTP body spanning segments is labeled as spanning rather than stitched, and there is no follow-stream. For reassembled application-layer traffic use [`grpcsnoop`](https://github.com/yeet-src/grpcsnoop) (gRPC), [`container-traffic`](https://github.com/yeet-src/container-traffic) (per-container HTTP), or a pcap plus Wireshark.
- **HTTP/2 headers stay HPACK-compressed.** Frames are identified by type, stream, and flags, and a HEADERS frame is labeled as carrying hpack-coded headers rather than decoded. Decoding HPACK needs the connection's dynamic table, which needs reassembly. [`grpcsnoop`](https://github.com/yeet-src/grpcsnoop) does that work.
- **1536 bytes per packet.** Anything past the snap length is not captured; the list still shows the true on-wire length, so a truncated packet is visible as one rather than silently short.
- **IPv6 extension headers are not walked.** The transport offset assumes the common no-extension case, and the protocol shown is the first next-header value. A packet with a routing or fragment header will have its L4 section misplaced.
- **No IP fragment reassembly.** Fragment flags and offsets are decoded and shown, but a fragmented packet's payload is not put back together, so payload identification only fires on the first fragment.
- **4000 packets of history, then the oldest go.** The ring trims 512 at a time. `c` clears it deliberately; there is no way to grow it from a flag.
- **A `--port` or `--proto` filter drops non-IP frames.** ARP and other link-level frames cannot match a port or an L4 protocol, so they are filtered out in the kernel along with everything else that does not match. Capture without a scope to see them.
- **One host, one capture, no persistence.** No fleet view, no aggregation across hosts, no saved captures, no query language, and no retention. Close the tool and the packets are gone. For cluster-wide traffic maps and history, that is what an APM, Pixie, or Coroot is for.
- **Mouse support needs a terminal that reports mouse events.** Nearly all modern ones do, and every mouse action has a keyboard equivalent regardless.

## FAQ

**Can I capture on loopback?**
It does now. Earlier versions greyed loopback out with a "tcx can't attach here" note, which was over-cautious: TCX attaches to `lo` fine, and traffic between local services is often the whole reason to capture. Select it in the picker, or skip straight to it with `yeet run gh:yeet-src/pktscope -- --iface lo`.

**Why does a packet show a `len` bigger than the bytes in the hex pane?**
`len` is the full on-wire frame length; the hex pane shows what was captured, capped at the 1536-byte snap length. The Frame section of the detail tree states both numbers side by side.

**My filter matches nothing, but packets are clearly arriving.**
The rail shows the terms as the compiler understood them plus a match count, so check that first: an unrecognized word silently became a substring match over the decoded text, which is much narrower than the term you meant. A kernel-side `--port` or `--proto` is a different thing entirely, and no display filter can widen it.

**Counters reset when I re-picked an interface.**
Leaving a capture with `←` tears the session down and starting a new one clears the ring, the counters, and the sequence numbers. Time and `#` are always relative to the current capture, not to when the process started.

**Does capturing slow down the traffic?**
The programs return `TCX_NEXT` on every path, so nothing is held or delayed. The cost is a ring-buffer reservation and a copy per *matched* packet, which is why `--port` and `--proto` matter on a busy interface: a non-matching packet is dropped in the kernel before any of that happens.

## License

The BPF program declares `Dual BSD/GPL`.

---

Built with [yeet](https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=pktscope&utm_content=footer), a JS runtime for writing eBPF programs on Linux machines. Join us on [discord](https://discord.gg/JxVseaAVAU).
