/* Display filter — compiles a query string into a per-packet predicate.
 *
 * Space-separated terms are ANDed; a term prefixed with `!` (or `-`) is
 * negated. Anything not recognized as a term falls back to a substring match
 * over the packet's searchable text, so a bare `ClaudeBot` or `10.0.0.7`
 * still works and nothing a user types is ever an error.
 *
 *   tls              payload identified as tls (also: http1 http2 dns text)
 *   tcp udp icmp     l4 protocol
 *   port 443         either endpoint (port:443 and port=443 work too)
 *   src 10.0.0.7     source / dest / either endpoint address
 *   dst 10.0.0.1
 *   host 10.0.0.1
 *   ua ClaudeBot     http user-agent (sni <name> for a tls server-name)
 *   syn rst fin      tcp flags (also: ack psh urg)
 *   rx  tx           direction
 *   data             carries payload
 *   len>500          length comparison (>, <, >=, <=, =)
 *   !ack             negation
 */
import { ETH_P_ARP, TCP, UDP, fieldValue, searchText } from "@/lib/proto.js";

const KIND_ALIAS = {
  tls: "tls",
  ssl: "tls",
  http1: "http/1",
  "http/1": "http/1",
  h1: "http/1",
  http2: "http/2",
  "http/2": "http/2",
  h2: "http/2",
  h2c: "http/2",
  dns: "dns",
  text: "text",
};

const FLAG_BITS = { syn: 0x02, ack: 0x10, psh: 0x08, fin: 0x01, rst: 0x04, urg: 0x20 };
const PROTO_NUM = { tcp: TCP, udp: UDP, icmp: 1, icmp6: 58, gre: 47, esp: 50, sctp: 132 };
const ARG_WORDS = new Set(["port", "src", "dst", "host", "ip", "sni", "ua", "kind"]);

// One term → a predicate, or null when the word isn't a known term (the
// caller then treats it as a substring match).
function termOf(word, arg) {
  const w = word.toLowerCase();

  if (ARG_WORDS.has(w)) {
    const a = (arg ?? "").toLowerCase();
    if (!a) return null;
    switch (w) {
      case "port": {
        const n = Number(a);
        return Number.isFinite(n) ? (p) => p.sport === n || p.dport === n : null;
      }
      case "src":
        return (p) => p.src.toLowerCase().includes(a);
      case "dst":
        return (p) => p.dst.toLowerCase().includes(a);
      case "host":
      case "ip":
        return (p) => p.src.toLowerCase().includes(a) || p.dst.toLowerCase().includes(a);
      case "kind":
        return (p) => (p.sum?.kind ?? "") === (KIND_ALIAS[a] ?? a);
      case "sni":
      case "ua": {
        const label = w === "ua" ? "user-agent" : "sni";
        return (p) => (fieldValue(p, label) ?? "").toLowerCase().includes(a);
      }
    }
  }

  if (KIND_ALIAS[w]) return (p) => p.sum?.kind === KIND_ALIAS[w];
  if (w === "arp") return (p) => !p.ver && p.ethertype === ETH_P_ARP;
  if (PROTO_NUM[w] != null) return (p) => p.ver !== 0 && p.l4 === PROTO_NUM[w];
  if (FLAG_BITS[w] != null) return (p) => p.l4 === TCP && (p.flags & FLAG_BITS[w]) !== 0;
  if (w === "rx") return (p) => !p.dir;
  if (w === "tx") return (p) => !!p.dir;
  if (w === "data") return (p) => p.length > p.payoff;

  const cmp = /^len\s*(>=|<=|>|<|=)\s*(\d+)$/.exec(w);
  if (cmp) {
    const n = Number(cmp[2]);
    switch (cmp[1]) {
      case ">": return (p) => p.length > n;
      case "<": return (p) => p.length < n;
      case ">=": return (p) => p.length >= n;
      case "<=": return (p) => p.length <= n;
      default: return (p) => p.length === n;
    }
  }
  return null;
}

/* Compile a query into { pred, terms } — `terms` names what was understood,
 * for the status rail. Returns null for an empty query (no filtering).
 */
export function compileFilter(q) {
  if (!q || !q.trim()) return null;

  // `len > 500` and `port: 443` are tokenized as one word so the spacing a
  // user happens to type doesn't change the meaning.
  const words = q
    .trim()
    .replace(/\s*(>=|<=|>|<|=)\s*/g, "$1")
    .replace(/([a-z]+)[:=]\s*/gi, "$1 ")
    .split(/\s+/);

  const preds = [];
  const terms = [];
  for (let i = 0; i < words.length; i++) {
    let w = words[i];
    let neg = false;
    if (w[0] === "!" || (w[0] === "-" && w.length > 1)) {
      neg = true;
      w = w.slice(1);
    }
    if (!w) continue;

    const takesArg = ARG_WORDS.has(w.toLowerCase());
    const arg = takesArg ? words[i + 1] : undefined;
    let pred = termOf(w, arg);
    if (pred && takesArg) i++;

    if (!pred) {
      const needle = w.toLowerCase();
      pred = (p) => searchText(p).includes(needle);
      terms.push(neg ? `!${w}` : w);
    } else {
      terms.push(`${neg ? "!" : ""}${w}${takesArg ? ` ${arg}` : ""}`);
    }
    preds.push(neg ? (p) => !pred(p) : pred);
  }

  if (!preds.length) return null;
  return { pred: (p) => preds.every((f) => f(p)), terms };
}

export const applyFilter = (list, compiled) => (compiled ? list.filter(compiled.pred) : list);
