// The protocol detail tree — Wireshark's middle pane. Sections (Frame /
// IP / TCP / Payload) fold with ⏎ or ←→; every row carries the byte range
// it decodes, which the hex pane highlights while this pane is focused.
// `detailView` exposes scroll geometry for click mapping.
import { Box, Text } from "yeet:tui";

import Cap from "@/components/cap.jsx";
import { current, tick } from "@/probes/capture.js";
import { buildTree, flatRows } from "@/lib/proto.js";
import {
  C_ANN, C_DIM, C_ETH, C_FAINT, C_IP, C_SEL_BG, C_SEL_FG, C_TITLE,
  clamp, l4Color, pad, trunc,
} from "@/lib/format.js";

// The field-label column tracks the pane width so values keep a usable
// share on a narrow terminal.
const labelW = (width) => clamp(9, Math.floor(width * 0.18), 15);

export const detailView = { top: 0, rows: [] }; // mutated on render, for click mapping

const secColor = (id, p) =>
  id === "eth" ? C_ETH : id === "ip" ? C_IP : id === "l4" ? l4Color(p.l4) : id === "payload" ? C_ANN : C_DIM;

export default function DetailTree({ height, width, focus, dSel, collapsed }) {
  let topMem = 0;

  return (
    <Box overflow="hidden">
      {() => {
        tick.get();
        const p = current();
        const vis = Math.max(1, height - 1);
        const focused = focus.get() === "detail";
        const head = (
          <Text height="1" break="none" fg={C_FAINT}>
            <Text bold fg={C_DIM}>{" ── "}</Text>
            <Cap n="2" />
            <Text bold fg={C_DIM}>{` fields ${focused ? "▸" : " "} `}</Text>
            <Text fg={C_FAINT}>{"─".repeat(Math.max(0, width - 20))}</Text>
            <Text fg={C_DIM}>{" ⇕ "}</Text>
          </Text>
        );
        if (!p) {
          detailView.top = 0;
          detailView.rows = [];
          return [head, <Text height="1" fg={C_DIM}>{"   select a packet"}</Text>];
        }

        const rows = flatRows((p.tree ??= buildTree(p)), collapsed.get());
        const cur = clamp(0, dSel.get(), rows.length - 1);
        let top = clamp(cur - vis + 1, topMem, cur);
        top = clamp(0, top, Math.max(0, rows.length - vis));
        topMem = top;
        detailView.top = top;
        detailView.rows = rows;

        const out = [head];
        const lw = labelW(width);
        for (let i = top; i < Math.min(rows.length, top + vis); i++) {
          const r = rows[i];
          const selRow = focused && i === cur;
          const cells = r.sec
            ? [
                <Text bold fg={selRow ? C_SEL_FG : secColor(r.id, p)}>
                  {` ${r.open ? "▾" : "▸"} ${trunc(r.title, width - 5)}`}
                </Text>,
              ]
            : [
                <Text fg={selRow ? C_SEL_FG : C_DIM}>{`     ${pad(r.label, lw)} `}</Text>,
                <Text fg={selRow ? C_SEL_FG : C_TITLE}>{trunc(r.value, Math.max(6, width - lw - 7))}</Text>,
              ];
          out.push(
            selRow ? (
              <Box height="1" direction="row" bg={C_SEL_BG}>
                <Text break="none">{cells}</Text>
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
