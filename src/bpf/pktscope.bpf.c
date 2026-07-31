// pktscope.bpf.c — a clsact/TCX packet tap for the pktscope viewer.
//
// Both hooks snap each packet from the start of its lowest header and
// stream it, headers plus payload, to the `events` ring buffer. Where the
// snap starts is per-interface: userspace marks ethernet-framed devices in
// `l2map` (ifindex → link header length), and those capture from the MAC
// header — including non-IP frames like ARP. Devices with no entry
// (raw-IP tunnels: tunl*/ipip/gre/tun/wg) capture from the network header,
// so tcpdump-era ethernet assumptions never break them. Userspace arms the
// tap by writing a `scope_cfg` (port/proto filter) into the `scope` array.
// The program is a passive observer: it always returns TCX_NEXT, never
// dropping or altering traffic.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Snap length, measured from the first captured byte (MAC or IP header).
// A full untagged ethernet MTU frame (14 + 1500) fits with room to spare.
#define CAP 1536

// bpf_skb_load_bytes_relative start points; not always in vmlinux.h.
#ifndef BPF_HDR_START_MAC
#define BPF_HDR_START_MAC 0
#endif
#ifndef BPF_HDR_START_NET
#define BPF_HDR_START_NET 1
#endif
// clsact/TCX passive return: continue the chain, touch nothing.
#ifndef TCX_NEXT
#define TCX_NEXT (-1)
#endif

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd

// The capture scope, set from userspace. `on == 0` streams nothing (attached
// but disarmed). `port == 0` matches any port, `proto == 0` any L4 protocol.
// Port is host byte order and only meaningful for TCP/UDP; when set, other
// protocols (and non-IP frames) are skipped.
struct scope_cfg {
	__u16 port;
	__u8 proto;
	__u8 on;
};
struct scope_cfg *_unused_cfg __attribute__((unused));

// One captured packet. Offsets index into `data`, whose byte 0 is the MAC
// header on ethernet-framed devices (l3off = link header length) and the IP
// header on raw-IP devices (l3off = 0) — so the viewer can colorize the
// link, IP, and L4 headers and the payload byte-for-byte. Non-IP frames
// carry ver == 0 and identify themselves by `ethertype` alone.
struct scope_pkt {
	__u64 ts_ns;
	__u32 ifindex;
	__u32 seq;
	__u32 ack;
	__u16 sport;
	__u16 dport;
	__u16 length; // full frame length on the wire
	__u16 caplen; // bytes captured into `data`
	__u16 l3off; // offset of the network header within `data`
	__u16 l4off; // offset of the L4 header within `data`
	__u16 payoff; // offset of the L4 payload within `data`
	__u16 win;
	__u16 ethertype;
	__u8 dir; // 0 = ingress (rx), 1 = egress (tx)
	__u8 ver; // 4, 6, or 0 for non-IP
	__u8 l4; // IPPROTO_*
	__u8 flags; // TCP flags
	__u8 ttl;
	__u8 _pad;
	__u8 saddr[16]; // v4 address lives in the first 4 bytes
	__u8 daddr[16];
	__u8 data[CAP];
};
struct scope_pkt *_unused_pkt __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scope_cfg);
} scope SEC(".maps");

// ifindex → link header length (14 for ethernet framing). A missing entry
// means the device hands us raw IP.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} l2map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline int rd(struct __sk_buff *skb, __u32 off, void *to, __u32 len)
{
	return bpf_skb_load_bytes_relative(skb, off, to, len, BPF_HDR_START_NET);
}

static __always_inline int tap(struct __sk_buff *skb, __u8 dir)
{
	__u32 zero = 0;
	struct scope_cfg *cfg = bpf_map_lookup_elem(&scope, &zero);
	if (!cfg || !cfg->on) {
		return TCX_NEXT;
	}

	__u32 ifindex = skb->ifindex;
	__u8 *l2p = bpf_map_lookup_elem(&l2map, &ifindex);
	const __u32 l2len = l2p ? *l2p : 0;
	const __u32 anchor = l2len ? BPF_HDR_START_MAC : BPF_HDR_START_NET;

	__u16 ethertype = 0;
	if (l2len) {
		__u16 et_n = 0;
		if (bpf_skb_load_bytes_relative(skb, l2len - 2, &et_n, 2, anchor) < 0) {
			return TCX_NEXT;
		}
		ethertype = bpf_ntohs(et_n);
	}

	// The IP version nibble decides the parse; on ethernet framing the
	// ethertype gates it, so an ARP body can't masquerade as IPv4.
	__u8 vbyte = 0;
	if (rd(skb, 0, &vbyte, 1) < 0) {
		vbyte = 0;
	}
	__u8 ver = vbyte >> 4;
	if (ver != 4 && ver != 6) {
		ver = 0;
	}
	if (l2len && ethertype != ETH_P_IP && ethertype != ETH_P_IPV6) {
		ver = 0;
	}
	if (!ver && (!l2len || cfg->port != 0 || cfg->proto != 0)) {
		// A raw-IP device gave us something unparseable, or a port/proto
		// filter is armed — non-IP frames can't match one.
		return TCX_NEXT;
	}

	__u8 proto = 0, ttl = 0;
	__u32 l4off = 0;
	__u32 l3len = 0; // full L3 packet length, from the IP header
	__u8 saddr[16] = {}, daddr[16] = {};
	if (ver == 4) {
		if (rd(skb, 9, &proto, 1) < 0) {
			return TCX_NEXT;
		}
		__u16 tot_n;
		rd(skb, 2, &tot_n, 2);
		l3len = bpf_ntohs(tot_n);
		rd(skb, 8, &ttl, 1);
		rd(skb, 12, saddr, 4);
		rd(skb, 16, daddr, 4);
		l4off = (vbyte & 0x0f) * 4;
		ethertype = ETH_P_IP;
	} else if (ver == 6) {
		// Extension headers aren't walked: l4off assumes the common
		// no-extension case, and `proto` is the first next-header.
		if (rd(skb, 6, &proto, 1) < 0) {
			return TCX_NEXT;
		}
		__u16 plen_n;
		rd(skb, 4, &plen_n, 2);
		l3len = 40 + bpf_ntohs(plen_n);
		rd(skb, 7, &ttl, 1);
		rd(skb, 8, saddr, 16);
		rd(skb, 24, daddr, 16);
		l4off = 40;
		ethertype = ETH_P_IPV6;
	}

	if (ver && cfg->proto != 0 && proto != cfg->proto) {
		return TCX_NEXT;
	}

	__u16 sport = 0, dport = 0, win = 0;
	__u32 seq = 0, ack = 0, l4hdr = 0;
	__u8 flags = 0;
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		__u16 sport_n, dport_n;
		if (rd(skb, l4off, &sport_n, 2) < 0 || rd(skb, l4off + 2, &dport_n, 2) < 0) {
			return TCX_NEXT;
		}
		sport = bpf_ntohs(sport_n);
		dport = bpf_ntohs(dport_n);
		l4hdr = 8;
	}
	if (cfg->port != 0 && sport != cfg->port && dport != cfg->port) {
		return TCX_NEXT;
	}

	if (proto == IPPROTO_TCP) {
		__u32 seq_n, ack_n;
		__u16 win_n;
		__u8 doff_b, flags_b;
		rd(skb, l4off + 4, &seq_n, 4);
		rd(skb, l4off + 8, &ack_n, 4);
		rd(skb, l4off + 12, &doff_b, 1);
		rd(skb, l4off + 13, &flags_b, 1);
		rd(skb, l4off + 14, &win_n, 2);
		seq = bpf_ntohl(seq_n);
		ack = bpf_ntohl(ack_n);
		win = bpf_ntohs(win_n);
		l4hdr = (doff_b >> 4) * 4;
		flags = flags_b;
	}

	// TCX pushes the link header back before running the program, so
	// skb->len is the full frame length on both hooks. IP packets prefer
	// the header-declared length, which excludes any ethernet pad.
	__u32 wire = ver ? l2len + l3len : skb->len;
	__u32 caplen = wire < CAP ? wire : CAP;

	struct scope_pkt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return TCX_NEXT;
	}
	/* A whole-struct memset is too large for clang to expand on the BPF
	 * target — zero the fixed header with the builtin and the capture
	 * buffer with an 8-byte-stride loop. The volatile store keeps clang's
	 * idiom recognizer from folding the loop back into a memset call.
	 */
	__builtin_memset(e, 0, __builtin_offsetof(struct scope_pkt, data));
	for (__u32 i = 0; i + 8 <= CAP; i += 8) {
		*(volatile __u64 *)&e->data[i] = 0;
	}
	e->ts_ns = bpf_ktime_get_ns();
	e->ifindex = skb->ifindex;
	e->seq = seq;
	e->ack = ack;
	e->sport = sport;
	e->dport = dport;
	e->length = wire;
	e->caplen = caplen;
	e->l3off = l2len;
	e->l4off = ver ? l2len + l4off : l2len;
	e->payoff = ver ? l2len + l4off + l4hdr : caplen;
	if (e->payoff > caplen) {
		e->payoff = caplen;
	}
	e->win = win;
	e->ethertype = ethertype;
	e->dir = dir;
	e->ver = ver;
	e->l4 = proto;
	e->flags = flags;
	e->ttl = ttl;
	__builtin_memcpy(e->saddr, saddr, 16);
	__builtin_memcpy(e->daddr, daddr, 16);
	/* Loopback/GSO skbs keep the payload paged, and the _relative loader
	 * only reaches the linear header area (EFAULT past it). Pull the frame
	 * linear so the payload reads land. The copy length is packet-derived,
	 * so the verifier needs a [1, CAP] range proven on the exact register
	 * passed to the helper. The barrier makes the value opaque FIRST —
	 * otherwise clang elides the clamp as provably dead, or fuses the
	 * range check into a decremented copy, and the branch refinement
	 * lands on a different register than the call argument. The signed
	 * lower-bound compare matters too: pre-6.8 verifiers don't lift umin
	 * on a != 0 branch, but have always refined JSGT.
	 */
	bpf_skb_pull_data(skb, skb->len);
	__u32 copy = caplen;
	barrier_var(copy);
	if (copy > CAP) {
		copy = CAP;
	}
	if ((__s32)copy > 0 &&
	    bpf_skb_load_bytes_relative(skb, 0, e->data, copy, anchor) < 0) {
		e->caplen = 0;
	}
	bpf_ringbuf_submit(e, 0);
	return TCX_NEXT;
}

SEC("tcx/ingress")
int tap_ingress(struct __sk_buff *skb)
{
	return tap(skb, 0);
}

SEC("tcx/egress")
int tap_egress(struct __sk_buff *skb)
{
	return tap(skb, 1);
}
