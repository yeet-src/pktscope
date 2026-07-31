/* Interface inventory for the picker: name, ifindex, state, kind, addresses,
 * and live packet rates from two consecutive stat samples. A from() signal —
 * the 1 s poll runs only while the picker is watching it.
 */
import { from } from "yeet:tui";

const QUERY = `{
  network_interfaces { name index is_up is_loopback ipv4 { address } ipv6 { address } }
  network_interface_stats { name recv_packets sent_packets }
}`;

function kindOf(i) {
  if (i.is_loopback) return "loopback";
  if (/^(tunl|ipip|sit|gre|gretap|ip6tnl|ip6gre)/.test(i.name)) return "tunnel";
  if (/^(wg|tun|tap|tailscale)/.test(i.name)) return "vpn";
  if (/^(veth|docker|br-|virbr|podman|cni|flannel|cali)/.test(i.name)) return "virtual";
  return "ether";
}

// Link header length: raw-IP devices (tunnels, tun/wg VPNs) hand the tap a
// bare IP packet; everything else — including loopback and tap — is
// ethernet-framed. gretap is L2 despite the tunnel kind.
function l2Of(i, kind) {
  if (/^(gretap|tap)/.test(i.name)) return 14;
  return kind === "tunnel" || kind === "vpn" ? 0 : 14;
}

export const ifaces = from((state) => {
  const prev = new Map();
  let prevAt = 0;

  const load = async () => {
    const { data } = await yeet.graph.query(QUERY);
    const stats = new Map();
    for (const s of data.network_interface_stats ?? []) stats.set(s.name, s);

    const now = Date.now();
    const dt = prevAt ? (now - prevAt) / 1000 : 0;
    prevAt = now;

    const rows = (data.network_interfaces ?? [])
      .map((i) => {
        const stat = stats.get(i.name);
        const was = prev.get(i.name);
        if (stat) prev.set(i.name, stat);
        const kind = kindOf(i);
        return {
          name: i.name,
          index: i.index,
          up: i.is_up,
          kind,
          l2: l2Of(i, kind),
          addrs: [...(i.ipv4 ?? []).map((a) => a.address), ...(i.ipv6 ?? []).map((a) => a.address)],
          rx: dt && was && stat ? Math.max(0, stat.recv_packets - was.recv_packets) / dt : null,
          tx: dt && was && stat ? Math.max(0, stat.sent_packets - was.sent_packets) / dt : null,
        };
      })
      .sort(
        (a, b) =>
          Number(b.up) - Number(a.up) ||
          Number(a.kind === "loopback") - Number(b.kind === "loopback") ||
          a.index - b.index,
      );
    state.set(rows);
  };

  const h = setInterval(() => load().catch(() => {}), 1000);
  load().catch(() => {});
  return () => clearInterval(h);
}, []);

// One-shot lookup for --iface: resolve names/indices without the picker.
export async function findIfaces(spec) {
  const { data } = await yeet.graph.query(QUERY);
  const all = data.network_interfaces ?? [];
  const wanted = String(spec).split(",").map((s) => s.trim()).filter(Boolean);
  const hits = wanted.map((w) => all.find((i) => i.name === w || String(i.index) === w));
  if (hits.some((h) => !h)) {
    throw new Error(`no such interface — have: ${all.map((i) => i.name).join(", ")}`);
  }
  return hits.map((i) => ({ name: i.name, index: i.index, l2: l2Of(i, kindOf(i)) }));
}
