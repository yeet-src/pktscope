/* BPF packet-tap engine. startScope() loads bin/probe.bpf.o, attaches the
 * TCX ingress+egress hooks on the chosen interfaces, arms the capture scope,
 * and streams normalized packets to `onPacket`. stop() detaches everything —
 * the per-capture mount/unmount lifecycle, so re-picking an interface
 * re-attaches cleanly.
 */
import { ArrayMap, BpfObject, HashMap, RingBuf } from "yeet:bpf";

import { ipStr, macStr } from "@/lib/proto.js";

function normalize(e) {
  const data = e.data instanceof Uint8Array ? e.data.subarray(0, e.caplen) : new Uint8Array();
  return {
    ts: Number(e.ts_ns),
    ifindex: e.ifindex,
    dir: e.dir, // 0 rx, 1 tx
    ver: e.ver,
    l4: e.l4,
    flags: e.flags,
    ttl: e.ttl,
    sport: e.sport,
    dport: e.dport,
    // Non-IP frames name their endpoints by MAC.
    src: e.ver ? ipStr(e.saddr, e.ver) : data.length >= 12 ? macStr(data, 6) : "—",
    dst: e.ver ? ipStr(e.daddr, e.ver) : data.length >= 12 ? macStr(data, 0) : "—",
    length: e.length,
    caplen: e.caplen,
    l3off: e.l3off,
    l4off: e.l4off,
    payoff: Math.min(e.payoff, e.caplen),
    ethertype: e.ethertype,
    win: e.win,
    seq: e.seq >>> 0,
    ack: e.ack >>> 0,
    data,
  };
}

export async function startScope({ ifaces, port = 0, proto = 0 }, onPacket) {
  const ifindexes = ifaces.map((i) => i.index);
  const obj = new BpfObject({ exe: "../bin/probe.bpf.o", base: import.meta.dirname });
  const control = await obj
    .bind("scope", { kind: "array" })
    .bind("l2map", { kind: "hash" })
    .bind("events", { kind: "ringbuf", btf_struct: "scope_pkt" })
    .attach("tap_ingress", { kind: "tcx", ifindex: ifindexes })
    .attach("tap_egress", { kind: "tcx", ifindex: ifindexes })
    .start();

  // Ethernet-framed devices capture from the MAC header; raw-IP tunnels
  // (no l2map entry) keep the network-header anchor.
  const l2map = new HashMap(control, "l2map");
  for (const i of ifaces) {
    if (i.l2) await l2map.update(i.index, i.l2);
  }

  const events = new RingBuf(control, "events");
  const sub = await events.subscribe((w) => {
    // The daemon masks throws in async callbacks as opaque errors — guard.
    try {
      onPacket(normalize(w?.scope_pkt ?? w));
    } catch {}
  });

  // Arm last, so the ring never fills before the subscriber is listening.
  const scope = new ArrayMap(control, "scope");
  await scope.update(0, { port, proto, on: 1 });

  return {
    id: control.id,
    async stop() {
      try {
        await sub.unsubscribe();
      } catch {}
      try {
        await control.stop();
      } catch {}
    },
  };
}
