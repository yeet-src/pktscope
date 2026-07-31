/* Protocol dissection — pure functions from a captured packet to structure.
 *
 * classify(p) identifies the payload (TLS records with SNI, HTTP/1 with its
 * headers, HTTP/2 preface + frames, DNS queries) and buildTree(p) turns the
 * whole packet into Wireshark-style sections of fields. Every section and
 * field carries a byte `range` [start, end) into p.data, so the hex pane can
 * highlight exactly the bytes a selected field decodes.
 */

export const TCP = 6;
export const UDP = 17;

export const PROTO_NAMES = { 1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmp6", 132: "sctp" };

export const ETH_P_ARP = 0x0806;
export const ETHERTYPES = {
  0x0800: "ipv4", 0x0806: "arp", 0x8035: "rarp", 0x8100: "vlan",
  0x86dd: "ipv6", 0x8863: "pppoe", 0x88cc: "lldp", 0x88e5: "macsec",
};

const ARP_OPS = { 1: "request", 2: "reply" };

const H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_TYPES = [
  "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
  "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION",
];
const TLS_CONTENT = { 20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData" };
const TLS_HANDSHAKE = {
  1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
  11: "Certificate", 12: "ServerKeyExchange", 14: "ServerHelloDone", 16: "ClientKeyExchange", 20: "Finished",
};
const TLS_VERSIONS = { 3: "TLS 1.2+", 4: "TLS 1.3" };
const HTTP1_RE = /^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|TRACE|CONNECT) \S+ HTTP\/1\.[01]|^HTTP\/1\.[01] \d{3}/;
const DNS_TYPES = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY" };

export function ipStr(bytes, ver) {
  if (ver === 4) return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // Collapse the longest run of zero groups to "::".
  return g.join(":").replace(/\b0(:0)+\b/, ":").replace(/:{3,}/, "::");
}

export function macStr(d, off = 0) {
  let s = "";
  for (let i = 0; i < 6; i++) s += (i ? ":" : "") + (d[off + i] ?? 0).toString(16).padStart(2, "0");
  return s;
}

export const etName = (t) => ETHERTYPES[t] ?? `0x${(t ?? 0).toString(16).padStart(4, "0")}`;

// The list/search protocol label: the L4 name for IP, the ethertype for
// link-level frames.
export const protoName = (p) => (p.ver ? PROTO_NAMES[p.l4] ?? String(p.l4) : etName(p.ethertype));

// Ordered for display: "PSH,ACK" / "SYN,ACK" / "FIN,ACK", ACK trailing.
const TCP_FLAGS = [
  [0x02, "SYN"], [0x01, "FIN"], [0x04, "RST"], [0x08, "PSH"],
  [0x20, "URG"], [0x10, "ACK"], [0x40, "ECE"], [0x80, "CWR"],
];
export function flagNames(f) {
  return TCP_FLAGS.filter(([b]) => f & b).map(([, n]) => n).join(",");
}

export function asciiOf(d, max = d.length) {
  let s = "";
  const n = Math.min(d.length, max);
  for (let i = 0; i < n; i++) {
    const b = d[i];
    s += b === 13 ? "\r" : b === 10 ? "\n" : b >= 32 && b < 127 ? String.fromCharCode(b) : "";
  }
  return s;
}

/* --- payload identification --- */

// Locate the SNI inside a ClientHello: returns { name, start, end } with
// offsets relative to the payload, or null.
function tlsSni(d, base) {
  // ClientHello body: version(2) random(32), then three variable-length
  // fields (session id, cipher suites, compression), then extensions.
  let i = base + 9 + 2 + 32;
  if (i >= d.length) return null;
  i += 1 + d[i];
  if (i + 2 > d.length) return null;
  i += 2 + ((d[i] << 8) | d[i + 1]);
  if (i + 1 > d.length) return null;
  i += 1 + d[i];
  if (i + 2 > d.length) return null;
  i += 2;
  while (i + 4 <= d.length) {
    const type = (d[i] << 8) | d[i + 1];
    const len = (d[i + 2] << 8) | d[i + 3];
    i += 4;
    if (type === 0) {
      if (i + 5 > d.length) return null;
      const nameLen = (d[i + 3] << 8) | d[i + 4];
      let name = "";
      for (let k = 0; k < nameLen && i + 5 + k < d.length; k++) name += String.fromCharCode(d[i + 5 + k]);
      return name ? { name, start: i + 5, end: Math.min(i + 5 + nameLen, d.length) } : null;
    }
    i += len;
  }
  return null;
}

function tlsClassify(pay, base) {
  if (pay.length < 5 || pay[0] < 20 || pay[0] > 23 || pay[1] !== 3 || pay[2] > 4) return null;

  const fields = [];
  const parts = [];
  let off = 0;
  let appdata = false;
  while (off + 5 <= pay.length && fields.length < 8 && pay[off] >= 20 && pay[off] <= 23 && pay[off + 1] === 3) {
    const len = (pay[off + 3] << 8) | pay[off + 4];
    const type = pay[off];
    let what = TLS_CONTENT[type];
    if (type === 23) appdata = true;
    if (type === 22 && off + 5 < pay.length && TLS_HANDSHAKE[pay[off + 5]]) what += ` ${TLS_HANDSHAKE[pay[off + 5]]}`;

    const end = Math.min(off + 5 + len, pay.length);
    fields.push({ label: "record", value: `${what} · ${len} B${end < off + 5 + len ? " (spans segments)" : ""}`, range: [base + off, base + end] });
    parts.push(what);
    if (type === 22 && pay[off + 5] === 1) {
      const sni = tlsSni(pay, off);
      if (sni) {
        fields.push({ label: "sni", value: sni.name, range: [base + sni.start, base + sni.end] });
        parts.push(`sni=${sni.name}`);
      }
    }
    off += 5 + len;
  }
  if (!fields.length) return null;

  // The record-layer version is legacy-frozen (0x0301 in ClientHellos) — only
  // trust it upward of 1.2.
  const ver = TLS_VERSIONS[pay[2]] ?? "TLS";
  if (appdata) fields.push({ label: "note", value: "encrypted payload — a plaintext-HTTP parser sees nothing here", range: [base, base + pay.length] });
  return { kind: "tls", info: `${ver} ${parts.join(" · ")}`, fields };
}

function http1Classify(pay, base) {
  const text = asciiOf(pay);
  if (!HTTP1_RE.test(text)) return null;

  const fields = [];
  let start = 0;
  let first = "";
  while (start < text.length && fields.length < 24) {
    let end = text.indexOf("\r\n", start);
    if (end < 0) end = text.length;
    const line = text.slice(start, end);
    if (line === "") {
      const bodyLen = pay.length - (end + 2);
      if (bodyLen > 0) fields.push({ label: "body", value: `${bodyLen} B captured`, range: [base + end + 2, base + pay.length] });
      break;
    }
    if (start === 0) {
      first = line;
      fields.push({ label: /^HTTP\//.test(line) ? "status" : "request", value: line, range: [base, base + end] });
    } else {
      const m = /^([^:]+):\s*(.*)$/.exec(line);
      fields.push({
        label: m ? m[1].toLowerCase() : "header",
        value: m ? m[2] : line,
        range: [base + start, base + end],
      });
    }
    start = end + 2;
  }
  return { kind: "http/1", info: first, fields };
}

function h2Classify(pay, base) {
  const fields = [];
  const parts = [];
  let off = 0;
  if (asciiOf(pay, 24) === H2_PREFACE) {
    fields.push({ label: "preface", value: "PRI * HTTP/2.0 — h2c, plaintext http/2", range: [base, base + 24] });
    parts.push("preface");
    off = 24;
  }

  while (off + 9 <= pay.length && fields.length < 10) {
    const len = (pay[off] << 16) | (pay[off + 1] << 8) | pay[off + 2];
    const type = pay[off + 3];
    const flags = pay[off + 4];
    const stream = (((pay[off + 5] << 24) | (pay[off + 6] << 16) | (pay[off + 7] << 8) | pay[off + 8]) >>> 0) & 0x7fffffff;
    if (type > 9 || len > 16384) break;

    const fl = [];
    if (type === 1 && flags & 0x4) fl.push("end_headers");
    if ((type === 0 || type === 1) && flags & 0x1) fl.push("end_stream");
    if ((type === 4 || type === 6) && flags & 0x1) fl.push("ack");
    const end = Math.min(off + 9 + len, pay.length);
    fields.push({
      label: H2_TYPES[type],
      value: `stream ${stream} · ${len} B${fl.length ? ` · ${fl.join(" ")}` : ""}${type === 1 ? " · hpack-coded headers" : ""}`,
      range: [base + off, base + end],
    });
    parts.push(H2_TYPES[type]);
    off += 9 + len;
  }
  if (!fields.length) return null;
  return { kind: "http/2", info: parts.join(" · "), fields };
}

// Length-prefixed DNS labels until a zero byte; pointers end the walk.
function dnsName(d, off) {
  const labels = [];
  let i = off;
  let guard = 0;
  while (i < d.length && guard++ < 32) {
    const n = d[i];
    if (n === 0) return { name: labels.join(".") || ".", next: i + 1 };
    if (n >= 0xc0) return { name: labels.join("."), next: i + 2 };
    if (i + 1 + n > d.length) return null;
    let label = "";
    for (let k = 0; k < n; k++) label += String.fromCharCode(d[i + 1 + k]);
    labels.push(label);
    i += 1 + n;
  }
  return null;
}

function dnsClassify(pay, base, p) {
  if (p.l4 !== UDP || (p.sport !== 53 && p.dport !== 53)) return null;
  if (pay.length < 12) return null;

  const qr = (pay[2] >> 7) & 1;
  const qdcount = (pay[4] << 8) | pay[5];
  const ancount = (pay[6] << 8) | pay[7];
  if (qdcount < 1) return null;
  const q = dnsName(pay, 12);
  if (!q) return null;

  const qtype = q.next + 2 <= pay.length ? (pay[q.next] << 8) | pay[q.next + 1] : 0;
  const type = DNS_TYPES[qtype] ?? (qtype ? `TYPE${qtype}` : "?");
  const what = qr ? "response" : "query";
  const fields = [
    { label: "id", value: `0x${((pay[0] << 8) | pay[1]).toString(16).padStart(4, "0")}`, range: [base, base + 2] },
    { label: what, value: `${type} ${q.name}`, range: [base + 12, base + Math.min(q.next + 4, pay.length)] },
  ];
  if (qr) fields.push({ label: "answers", value: String(ancount), range: [base + 6, base + 8] });
  return { kind: "dns", info: `${what} ${type} ${q.name}`, fields };
}

function textClassify(pay, base) {
  const n = Math.min(pay.length, 72);
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const b = pay[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
  }
  if (!n || printable / n < 0.85) return null;
  const first = asciiOf(pay, 72).split(/\r?\n/)[0].slice(0, 64);
  return { kind: "text", info: `“${first}”`, fields: [{ label: "text", value: first, range: [base, base + n] }] };
}

// Decode an ethernet/IPv4 ARP body at l3off; null when it isn't one.
function arpParse(p) {
  const d = p.data;
  const b = p.l3off;
  if (!b || p.ethertype !== ETH_P_ARP || d.length < b + 28) return null;
  if (rd16(d, b) !== 1 || rd16(d, b + 2) !== 0x0800) return null;

  const oper = rd16(d, b + 6);
  const sha = macStr(d, b + 8);
  const spa = ipStr(d.subarray(b + 14, b + 18), 4);
  const tha = macStr(d, b + 18);
  const tpa = ipStr(d.subarray(b + 24, b + 28), 4);
  const info = oper === 1 ? `who has ${tpa}? tell ${spa}` : oper === 2 ? `${spa} is at ${sha}` : `op ${oper}`;
  return { oper, sha, spa, tha, tpa, info };
}

// Identify the payload. Order matters: TLS and DNS are unambiguous, HTTP/1
// has a strict start-line, and the HTTP/2 frame heuristic goes last.
export function classify(p) {
  if (!p.ver) return null;
  const pay = p.data.subarray(p.payoff);
  if (!pay.length) return null;
  const base = p.payoff;
  return (
    dnsClassify(pay, base, p) ??
    tlsClassify(pay, base) ??
    http1Classify(pay, base) ??
    h2Classify(pay, base) ??
    textClassify(pay, base)
  );
}

/* --- search text --- */

/* Everything about a packet a bare filter word can match: endpoints, protocol,
 * the summary, every decoded field (so a `user-agent` header or an SNI is
 * findable), and the printable run of the payload itself — the "just grep the
 * bytes" case. Cached per packet; non-printables become spaces so a match
 * can't span a binary gap.
 */
export function searchText(p) {
  if (p.search != null) return p.search;

  const cls = (p.cls ??= classify(p));
  const parts = [
    `${p.src}:${p.sport}`,
    `${p.dst}:${p.dport}`,
    protoName(p),
    p.l4 === TCP ? flagNames(p.flags) : "",
    cls?.kind ?? "",
    p.sum?.info ?? cls?.info ?? "",
  ];
  for (const f of cls?.fields ?? []) parts.push(f.label, String(f.value));

  if (p.payoff < p.caplen) {
    let s = "";
    for (let i = p.payoff; i < p.caplen; i++) {
      const b = p.data[i];
      s += b >= 32 && b < 127 ? String.fromCharCode(b) : " ";
    }
    parts.push(s);
  }
  return (p.search = parts.join(" ").toLowerCase());
}

// Value of a decoded field by label (user-agent, sni, host, …).
export const fieldValue = (p, label) =>
  (p.cls?.fields ?? []).find((f) => f.label === label)?.value ?? null;

/* --- list-row summary --- */

// One line for the packet list's Info column, plus the row-color kind.
export function summarize(p) {
  if (!p.ver) {
    const arp = arpParse(p);
    if (arp) return { kind: "arp", info: arp.info };
    return { kind: null, info: `${etName(p.ethertype)} · ${p.length} B` };
  }
  const cls = (p.cls ??= classify(p));
  const paylen = Math.max(0, p.length - p.payoff);
  if (cls) return { kind: cls.kind, info: cls.info };
  if (p.l4 === TCP) {
    const f = flagNames(p.flags) || "·";
    return { kind: null, info: paylen ? `[${f}] ${paylen} B` : `[${f}] seq=${p.seq}` };
  }
  if (p.l4 === UDP) return { kind: null, info: `${paylen} B` };
  return { kind: null, info: PROTO_NAMES[p.l4] ?? `proto ${p.l4}` };
}

/* --- detail tree --- */

const rd16 = (d, o) => (d[o] << 8) | d[o + 1];

// Wireshark-style sections for one packet. Field values fall back to raw
// header bytes when the tap didn't pre-parse them.
export function buildTree(p) {
  const d = p.data;
  const b = p.l3off;
  const sections = [];
  const paylen = Math.max(0, p.length - p.payoff);

  sections.push({
    id: "frame",
    title: `Frame · ${p.length} B on wire · ${p.caplen} B captured`,
    range: [0, p.caplen],
    fields: [
      { label: "direction", value: p.dir ? "egress (tx)" : "ingress (rx)", range: [0, 0] },
      { label: "interface", value: `ifindex ${p.ifindex}`, range: [0, 0] },
    ],
  });

  if (b && d.length >= b) {
    sections.push({
      id: "eth",
      title: `Ethernet · ${macStr(d, 6)} → ${macStr(d, 0)}`,
      range: [0, b],
      fields: [
        { label: "dest", value: macStr(d, 0), range: [0, 6] },
        { label: "source", value: macStr(d, 6), range: [6, 12] },
        { label: "type", value: `${etName(p.ethertype)} (0x${p.ethertype.toString(16).padStart(4, "0")})`, range: [b - 2, b] },
      ],
    });
  }

  if (p.ver === 4) {
    const df = (d[b + 6] & 0x40) !== 0;
    const mf = (d[b + 6] & 0x20) !== 0;
    const fragOff = rd16(d, b + 6) & 0x1fff;
    const fields = [
      { label: "version", value: `4 · header ${p.l4off - b} B`, range: [b, b + 1] },
      { label: "dscp", value: `0x${(d[b + 1] ?? 0).toString(16).padStart(2, "0")}`, range: [b + 1, b + 2] },
      { label: "length", value: String(rd16(d, b + 2)), range: [b + 2, b + 4] },
      { label: "ident", value: `0x${rd16(d, b + 4).toString(16).padStart(4, "0")}`, range: [b + 4, b + 6] },
      { label: "flags", value: `${df ? "DF" : ""}${mf ? " MF" : ""}${fragOff ? ` frag=${fragOff}` : ""}`.trim() || "—", range: [b + 6, b + 8] },
      { label: "ttl", value: String(p.ttl), range: [b + 8, b + 9] },
      { label: "protocol", value: `${PROTO_NAMES[p.l4] ?? "?"} (${p.l4})`, range: [b + 9, b + 10] },
      { label: "checksum", value: `0x${rd16(d, b + 10).toString(16).padStart(4, "0")}`, range: [b + 10, b + 12] },
      { label: "source", value: p.src, range: [b + 12, b + 16] },
      { label: "dest", value: p.dst, range: [b + 16, b + 20] },
    ];
    if (p.l4off - b > 20) fields.push({ label: "options", value: `${p.l4off - b - 20} B`, range: [b + 20, p.l4off] });
    sections.push({ id: "ip", title: `IPv4 · ${p.src} → ${p.dst}`, range: [b, p.l4off], fields });
  } else if (p.ver === 6) {
    sections.push({
      id: "ip",
      title: `IPv6 · ${p.src} → ${p.dst}`,
      range: [b, p.l4off],
      fields: [
        { label: "length", value: String(rd16(d, b + 4)), range: [b + 4, b + 6] },
        { label: "next hdr", value: `${PROTO_NAMES[p.l4] ?? "?"} (${p.l4})`, range: [b + 6, b + 7] },
        { label: "hop limit", value: String(p.ttl), range: [b + 7, b + 8] },
        { label: "source", value: p.src, range: [b + 8, b + 24] },
        { label: "dest", value: p.dst, range: [b + 24, b + 40] },
      ],
    });
  }

  const lo = p.l4off;
  if (!p.ver) {
    const arp = arpParse(p);
    if (arp) {
      sections.push({
        id: "l4",
        title: `ARP · ${arp.info}`,
        range: [lo, Math.min(lo + 28, p.caplen)],
        fields: [
          { label: "opcode", value: `${ARP_OPS[arp.oper] ?? "?"} (${arp.oper})`, range: [lo + 6, lo + 8] },
          { label: "sender mac", value: arp.sha, range: [lo + 8, lo + 14] },
          { label: "sender ip", value: arp.spa, range: [lo + 14, lo + 18] },
          { label: "target mac", value: arp.tha, range: [lo + 18, lo + 24] },
          { label: "target ip", value: arp.tpa, range: [lo + 24, lo + 28] },
        ],
      });
    } else {
      sections.push({
        id: "l4",
        title: etName(p.ethertype).toUpperCase(),
        range: [lo, p.caplen],
        fields: [{ label: "header + data", value: `${Math.max(0, p.caplen - lo)} B captured`, range: [lo, p.caplen] }],
      });
    }
    return sections;
  }

  if (p.l4 === TCP) {
    const hdr = p.payoff - lo;
    const fields = [
      { label: "src port", value: String(p.sport), range: [lo, lo + 2] },
      { label: "dst port", value: String(p.dport), range: [lo + 2, lo + 4] },
      { label: "seq", value: String(p.seq), range: [lo + 4, lo + 8] },
      { label: "ack", value: String(p.ack), range: [lo + 8, lo + 12] },
      { label: "flags", value: flagNames(p.flags) || "—", range: [lo + 13, lo + 14] },
      { label: "window", value: String(p.win), range: [lo + 14, lo + 16] },
      { label: "checksum", value: `0x${rd16(d, lo + 16).toString(16).padStart(4, "0")}`, range: [lo + 16, lo + 18] },
    ];
    if (hdr > 20) fields.push({ label: "options", value: `${hdr - 20} B`, range: [lo + 20, p.payoff] });
    sections.push({ id: "l4", title: `TCP · ${p.sport} → ${p.dport} [${flagNames(p.flags) || "·"}]`, range: [lo, p.payoff], fields });
  } else if (p.l4 === UDP) {
    sections.push({
      id: "l4",
      title: `UDP · ${p.sport} → ${p.dport}`,
      range: [lo, p.payoff],
      fields: [
        { label: "src port", value: String(p.sport), range: [lo, lo + 2] },
        { label: "dst port", value: String(p.dport), range: [lo + 2, lo + 4] },
        { label: "length", value: String(rd16(d, lo + 4)), range: [lo + 4, lo + 6] },
        { label: "checksum", value: `0x${rd16(d, lo + 6).toString(16).padStart(4, "0")}`, range: [lo + 6, lo + 8] },
      ],
    });
  } else {
    sections.push({
      id: "l4",
      title: `${(PROTO_NAMES[p.l4] ?? `proto ${p.l4}`).toUpperCase()}`,
      range: [lo, p.caplen],
      fields: [{ label: "header + data", value: `${p.caplen - lo} B captured`, range: [lo, p.caplen] }],
    });
  }

  const cls = (p.cls ??= classify(p));
  sections.push({
    id: "payload",
    title: `Payload · ${paylen} B${cls ? ` · ${cls.kind}` : ""}`,
    range: [p.payoff, p.caplen],
    fields: cls?.fields ?? (paylen ? [{ label: "data", value: `${paylen} B (${p.caplen - p.payoff} captured)`, range: [p.payoff, p.caplen] }] : []),
  });

  return sections;
}

// Flatten the tree for the detail pane: one row per section header, plus its
// fields when the section isn't collapsed.
export function flatRows(tree, collapsed) {
  const rows = [];
  for (const s of tree) {
    const open = !collapsed.has(s.id);
    rows.push({ sec: true, id: s.id, title: s.title, range: s.range, open });
    if (open) for (const f of s.fields) rows.push({ sec: false, id: s.id, label: f.label, value: f.value, range: f.range });
  }
  return rows;
}
