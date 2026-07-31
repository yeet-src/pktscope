// Interface picker: a live table (name, state, kind, address, packet rates)
// navigated with ↑↓, ⏎ to start capturing. One column spec drives the header
// and the rows, and columns drop by priority on a narrow terminal. `lo` is
// listed but not selectable — the kernel refuses TCX there.
import { Box, Text } from "yeet:tui";

import { ifaces } from "@/probes/ifaces.js";
import {
  C_BAD, C_BRAND, C_DIM, C_FAINT, C_RX, C_SEL_BG, C_SEL_FG, C_TX,
  cellText, fitCols, fmtCount, headerLine,
} from "@/lib/format.js";

export const selectable = (r) => r.kind !== "loopback";

const SPEC = [
  { key: "mark", label: "", w: 1 },
  { key: "name", label: "interface", flex: 1, min: 10, max: 18 },
  { key: "state", label: "state", w: 5, prio: 3 },
  { key: "kind", label: "kind", w: 8, prio: 2 },
  { key: "addr", label: "address", flex: 1, min: 10, max: 40 },
  { key: "rx", label: "rx/s", w: 8, align: "r", prio: 4 },
  { key: "tx", label: "tx/s", w: 8, align: "r", prio: 4 },
  { key: "note", label: "", flex: 2, min: 0, prio: 1 },
];

export default ({ sel, height, width }) => (
  <Box overflow="hidden">
    <Text height="1">{" "}</Text>
    <Text height="1" bold fg={C_DIM} break="none">
      {() => headerLine(fitCols(SPEC, width - 3), "   ")}
    </Text>
    <Box overflow="hidden">
      {() => {
        const rows = ifaces.get();
        if (!rows.length) return [<Text height="1" fg={C_DIM}>{"   scanning interfaces…"}</Text>];

        const cols = fitCols(SPEC, width - 3);
        const i0 = Math.min(sel.get(), rows.length - 1);

        return rows.slice(0, Math.max(1, height - 3)).map((r, i) => {
          const selRow = i === i0;
          const value = {
            mark: selRow ? "▸" : " ",
            name: r.name,
            state: r.up ? "up" : "down",
            kind: r.kind,
            addr: r.addrs[0] ?? "—",
            rx: r.rx == null ? "—" : fmtCount(r.rx),
            tx: r.tx == null ? "—" : fmtCount(r.tx),
            note: selectable(r) ? "" : "tcx can't attach here",
          };
          const line = cols.reduce(
            (acc, c, ci) => acc + cellText(c, value[c.key]) + (ci === cols.length - 1 ? "" : " "),
            "  ",
          );

          if (selRow) {
            return (
              <Box height="1" direction="row" bg={C_SEL_BG}>
                <Text break="none" bold fg={C_SEL_FG}>{line}</Text>
              </Box>
            );
          }
          const color = {
            mark: C_DIM,
            name: r.up ? C_BRAND : C_FAINT,
            state: r.up ? C_RX : C_BAD,
            kind: C_DIM,
            addr: C_DIM,
            rx: C_RX,
            tx: C_TX,
            note: C_FAINT,
          };
          return (
            <Text height="1" break="none">
              <Text>{"  "}</Text>
              {cols.map((c, ci) => (
                <Text fg={color[c.key]}>
                  {cellText(c, value[c.key]) + (ci === cols.length - 1 ? "" : " ")}
                </Text>
              ))}
            </Text>
          );
        });
      }}
    </Box>
  </Box>
);
