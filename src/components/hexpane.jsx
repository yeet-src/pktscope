// The hex pane — Wireshark's bottom pane. Every byte is colored by the
// section it belongs to (ethernet / IP header / L4 header / payload), and
// the byte range of the field selected in the detail tree glows on a
// highlight background. Auto-scrolls to keep the highlighted range in view;
// the wheel adds a manual offset on top via the `scroll` signal.
import { Box, Text } from "yeet:tui";

import Cap from "@/components/cap.jsx";
import { current, tick } from "@/probes/capture.js";
import {
  C_ANN, C_DIM, C_ETH, C_FAINT, C_HL_BG, C_IP, C_PAY, C_SEL_FG,
  clamp, hx, l4Color, lpad,
} from "@/lib/format.js";

// Bytes per row: 16 needs offset(7) + 3/byte + a mid gap + the ascii gutter.
// Halve it rather than wrap or clip when the terminal is too narrow.
const perRow = (width) => (width >= 7 + 16 * 3 + 1 + 1 + 16 ? 16 : 8);

// Merge per-byte faces into contiguous <Text> spans.
function spans(cells) {
  const out = [];
  let run = null;
  for (const c of cells) {
    if (run && run.fg === c.fg && run.bg === c.bg) run.t += c.t;
    else out.push((run = { t: c.t, fg: c.fg, bg: c.bg }));
  }
  return out.map((r) => (r.bg ? <Text fg={r.fg} bg={r.bg}>{r.t}</Text> : <Text fg={r.fg}>{r.t}</Text>));
}

export default function HexPane({ height, width, selRange, scroll }) {
  return (
    <Box overflow="hidden">
      {() => {
        tick.get();
        const p = current();
        const lines = Math.max(1, height - 1);
        const l4c = p ? l4Color(p.l4) : C_DIM;

        // The legend is the first thing to go when the pane gets narrow: the
        // snap note (how much of the packet was captured) matters more.
        const note = p && p.length > p.caplen ? ` · ${p.caplen} of ${p.length} B captured` : "";
        const legend = width - note.length >= 68;
        const head = (
          <Text height="1" break="none">
            <Text bold fg={C_DIM}>{" ── "}</Text>
            <Cap n="3" />
            <Text bold fg={C_DIM}>{" bytes "}</Text>
            {legend ? <Text fg={C_ETH}>{"■ eth "}</Text> : null}
            {legend ? <Text fg={C_IP}>{"■ ip "}</Text> : null}
            {legend ? <Text fg={l4c}>{"■ l4 "}</Text> : null}
            {legend ? <Text fg={C_PAY}>{"■ payload "}</Text> : null}
            {legend ? <Text fg={C_ANN}>{"■ selected field "}</Text> : null}
            <Text fg={C_FAINT}>
              {"─".repeat(Math.max(0, width - (legend ? 58 : 17) - note.length)) + note}
            </Text>
            <Text fg={C_DIM}>{" ⇕ "}</Text>
          </Text>
        );
        if (!p || !p.caplen) return [head, <Text height="1" fg={C_DIM}>{"   no bytes"}</Text>];

        const bpr = perRow(width);
        const r = selRange.get();
        const hl = r && r[1] > r[0] && r[0] < p.caplen ? r : null;
        const total = Math.ceil(p.caplen / bpr);
        let top = 0;
        if (hl) {
          const first = Math.floor(hl[0] / bpr);
          const last = Math.floor(Math.min(hl[1] - 1, p.caplen - 1) / bpr);
          const span = last - first + 1;
          top = clamp(0, first - Math.max(0, (lines - span) >> 1), Math.max(0, total - lines));
        }
        top = clamp(0, top + scroll.get(), Math.max(0, total - lines));

        const out = [head];
        for (let li = top; li < Math.min(total, top + lines); li++) {
          const off = li * bpr;
          const hexCells = [];
          const ascCells = [];
          for (let j = 0; j < bpr; j++) {
            const idx = off + j;
            const gap = j === bpr >> 1 ? " " : "";
            if (idx >= p.caplen) {
              hexCells.push({ t: `${gap}   `, fg: C_FAINT, bg: null });
              continue;
            }
            const b = p.data[idx];
            const printable = b >= 32 && b < 127;
            const inHl = hl && idx >= hl[0] && idx < hl[1];
            const fg = inHl ? C_SEL_FG : idx < p.l3off ? C_ETH : idx < p.l4off ? C_IP : idx < p.payoff ? l4c : printable ? C_PAY : C_DIM;
            const bg = inHl ? C_HL_BG : null;
            // The inter-byte space joins the highlight only mid-range, so the
            // bar hugs the range's ends.
            const joint = hl && idx + 1 > hl[0] && idx + 1 < hl[1] && idx + 1 < p.caplen;
            hexCells.push({ t: `${gap}${hx(b)}`, fg, bg });
            hexCells.push({ t: " ", fg, bg: joint ? C_HL_BG : null });
            ascCells.push({ t: printable ? String.fromCharCode(b) : "·", fg, bg });
          }
          out.push(
            <Text height="1" break="none">
              <Text fg={C_FAINT}>{` ${lpad(off.toString(16).padStart(4, "0"), 5)}  `}</Text>
              {spans(hexCells)}
              <Text>{" "}</Text>
              {spans(ascCells)}
            </Text>,
          );
        }
        return out;
      }}
    </Box>
  );
}
