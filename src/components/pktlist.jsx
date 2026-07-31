// The packet list — Wireshark's top pane. One column spec drives the header
// and every row, so they stay aligned at any width; columns drop by priority
// as the terminal narrows (len, then time and #, then the → separator, then
// proto), and source/destination/info share what's left. Rows are colored by
// identified payload kind; the selection is a full-width bar. `listView`
// exposes the live scroll geometry so main.jsx can map clicks to rows.
import { Box, Text } from "yeet:tui";

import { pkts, sel, startTs, tick } from "@/probes/capture.js";
import { applyFilter } from "@/lib/filter.js";
import { TCP, UDP, protoName } from "@/lib/proto.js";
import {
  C_BAD, C_DIM, C_FAINT, C_RX, C_SEL_BG, C_SEL_FG, C_TX, KIND_FG,
  cellText, clamp, fitCols, headerLine, l4Color,
} from "@/lib/format.js";

export const listView = { top: 0, rows: [] }; // mutated on render, for click mapping

const SPEC = [
  { key: "no", label: "#", w: 5, align: "r", prio: 2 },
  { key: "time", label: "time", w: 9, align: "r", prio: 3 },
  { key: "dir", label: "", w: 1 },
  { key: "src", label: "source", flex: 1, min: 15, max: 27 },
  { key: "arrow", label: "", w: 1, prio: 5 },
  { key: "dst", label: "destination", flex: 1, min: 15, max: 27 },
  { key: "proto", label: "proto", w: 5, prio: 4 },
  { key: "len", label: "len", w: 6, align: "r", prio: 1 },
  { key: "info", label: "info", flex: 2, min: 10 },
];

export default function PktList({ height, width, filter, focus }) {
  let topMem = 0;

  return (
    <Box overflow="hidden">
      {() => {
        tick.get();
        const q = filter.get();
        const rows = applyFilter(pkts, q);
        const vis = Math.max(1, height - 1);
        const cols = fitCols(SPEC, width - 1);

        const head = (
          <Text height="1" bold fg={C_DIM} break="none">
            {headerLine(cols)}
          </Text>
        );

        if (!rows.length) {
          listView.top = 0;
          listView.rows = [];
          return [
            head,
            <Text height="1" fg={C_DIM}>
              {q ? `   no packets match “${q.terms.join(" ")}”` : "   waiting for packets…"}
            </Text>,
            <Text height="1" fg={C_FAINT}>
              {q ? "   filters: tls · http2 · dns · tcp · port 443 · host 10.0.0.1 · syn · rx · data · len>500 · !ack" : ""}
            </Text>,
          ];
        }

        const cur = pkts[Math.min(sel.get(), pkts.length - 1)];
        let pos = rows.indexOf(cur);
        if (pos < 0) pos = rows.length - 1;
        let top = clamp(pos - vis + 1, topMem, pos);
        top = clamp(0, top, Math.max(0, rows.length - vis));
        topMem = top;
        listView.top = top;
        listView.rows = rows;

        const t0 = startTs();
        const focused = focus.get() === "list";
        const out = [head];

        for (let i = top; i < Math.min(rows.length, top + vis); i++) {
          const p = rows[i];
          const hasPorts = p.l4 === TCP || p.l4 === UDP;
          const rst = p.l4 === TCP && p.flags & 0x04;
          const kindC = rst ? C_BAD : (KIND_FG[p.sum.kind] ?? C_DIM);
          const value = {
            no: p.no,
            time: ((p.ts - t0) / 1e9).toFixed(3),
            dir: p.dir ? "▲" : "▼",
            src: hasPorts ? `${p.src}:${p.sport}` : p.src,
            arrow: "→",
            dst: hasPorts ? `${p.dst}:${p.dport}` : p.dst,
            proto: protoName(p),
            len: p.length,
            info: p.sum.info,
          };
          const color = {
            no: C_FAINT,
            time: C_DIM,
            dir: p.dir ? C_TX : C_RX,
            arrow: C_DIM,
            proto: l4Color(p.l4),
            len: C_DIM,
            info: kindC,
          };

          const cells = [<Text>{" "}</Text>];
          cols.forEach((c, ci) => {
            const t = cellText(c, value[c.key]) + (ci === cols.length - 1 ? "" : " ");
            cells.push(<Text fg={color[c.key]}>{t}</Text>);
          });

          out.push(
            i === pos ? (
              <Box height="1" direction="row" bg={C_SEL_BG}>
                <Text break="none" bold={focused} fg={C_SEL_FG}>
                  {cols.reduce(
                    (acc, c, ci) => acc + cellText(c, value[c.key]) + (ci === cols.length - 1 ? "" : " "),
                    " ",
                  )}
                </Text>
              </Box>
            ) : (
              <Text height="1" break="none">{cells}</Text>
            ),
          );
        }
        return out;
      }}
    </Box>
  );
}
