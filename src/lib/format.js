// Pure presentation helpers — strings and the shared palette. No signals,
// no BPF. Imported by the components through the `@/` alias.
import { rgb } from "yeet:tui";

export const pad = (s, n) => (String(s) + " ".repeat(n)).slice(0, n);
export const lpad = (s, n) => (" ".repeat(n) + String(s)).slice(-n);
export const trunc = (s, w) => {
  s = String(s ?? "");
  return s.length > w ? s.slice(0, Math.max(0, w - 1)) + "…" : s;
};
export const hx = (b) => b.toString(16).padStart(2, "0");
export const clamp = (lo, v, hi) => Math.max(lo, Math.min(hi, v));

export const fmtCount = (n) => {
  if (n == null) return "—";
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(Math.round(n));
};

export const fmtBytes = (n) => {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${n} B`;
};

/* --- responsive table columns --- */

/* One spec drives both the header and every row, so they can't drift out of
 * alignment. Columns are dropped cheapest-first (ascending `prio`; omit
 * `prio` to make one mandatory) until the table fits, then the leftover
 * width is shared among `flex` columns by weight, honoring `min`/`max`.
 */
export function fitCols(spec, width) {
  const cols = spec.map((c) => ({ ...c, w: c.flex ? (c.min ?? 8) : c.w }));
  const need = () => cols.reduce((s, c) => s + c.w, 0) + Math.max(0, cols.length - 1);

  while (cols.length > 1 && need() > width) {
    let worst = -1;
    cols.forEach((c, i) => {
      if (c.prio != null && (worst < 0 || c.prio < cols[worst].prio)) worst = i;
    });
    if (worst < 0) break;
    cols.splice(worst, 1);
  }

  const flex = cols.filter((c) => c.flex);
  let slack = width - need();
  const room = (c) => c.w < (c.max ?? Infinity);
  while (slack > 0 && flex.some(room)) {
    for (const c of flex) {
      for (let k = 0; k < c.flex && slack > 0 && room(c); k++) {
        c.w++;
        slack--;
      }
    }
  }
  return cols;
}

export const cellText = (c, v) =>
  c.align === "r" ? lpad(trunc(v, c.w), c.w) : pad(trunc(v, c.w), c.w);

export const headerLine = (cols, lead = " ") =>
  lead + cols.map((c) => cellText(c, c.label ?? "")).join(" ");

/* --- palette (shared by every pane, so the colors teach the structure) --- */

export const C_BRAND = rgb(125, 211, 252);
export const C_TITLE = rgb(240, 246, 252);
export const C_DIM = rgb(120, 130, 140);
export const C_FAINT = rgb(80, 88, 98);
export const C_ETH = rgb(163, 230, 53); // ethernet header — lime
export const C_IP = rgb(125, 211, 252); // IP header — sky blue
export const C_TCP = rgb(199, 168, 255); // TCP header — violet
export const C_UDP = rgb(94, 234, 212); // UDP header — teal
export const C_L4X = rgb(253, 186, 116); // other L4 — apricot
export const C_PAY = rgb(235, 240, 245); // payload, printable
export const C_ANN = rgb(250, 204, 21); // payload identification — gold
export const C_RX = rgb(74, 222, 128); // ingress — green
export const C_TX = rgb(251, 146, 60); // egress — orange
export const C_BAD = rgb(248, 113, 113); // RST / errors — red
export const C_SEL_BG = rgb(38, 66, 104); // selection bar
export const C_SEL_FG = rgb(255, 255, 255);
export const C_HL_BG = rgb(96, 74, 20); // hex byte-range highlight (gold-brown)
export const C_RAIL = rgb(28, 32, 38); // title/footer rail background
export const C_CAP = rgb(52, 58, 66); // footer key-cap tile

// Row/label color for an identified payload kind.
export const KIND_FG = {
  arp: rgb(163, 230, 53),
  tls: rgb(212, 180, 255),
  "http/1": rgb(134, 239, 172),
  "http/2": rgb(103, 232, 249),
  dns: rgb(94, 234, 212),
  text: rgb(235, 240, 245),
};

export const l4Color = (l4) => (l4 === 6 ? C_TCP : l4 === 17 ? C_UDP : C_L4X);
