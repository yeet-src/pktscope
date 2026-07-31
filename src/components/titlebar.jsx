// Status rail: brand, capture target, live counters, and the capture state
// (● live / ⏸ paused / ⏹ stopped). One row, bg-tinted via the container.
import { Box, Text } from "yeet:tui";

import Cap from "@/components/cap.jsx";
import { pkts, follow, paused, stats, status } from "@/probes/capture.js";
import { C_ANN, C_BAD, C_BRAND, C_DIM, C_RAIL, C_RX, C_TITLE, C_TX, fmtBytes } from "@/lib/format.js";

const sep = () => <Text fg={C_DIM}>{"  ▏ "}</Text>;

// Counting is O(ring), and the rail re-renders on the publish tick, not per
// packet — cheap enough, and it tells you a filter is too tight at a glance.
function countMatches(q) {
  let n = 0;
  for (const p of pkts) if (q.pred(p)) n++;
  return n;
}

export default ({ view, filter, scope, panes, zoom }) => (
  <Box height="1" direction="row" bg={C_RAIL}>
    <Text break="none">
      {() => {
        const out = [<Text bold fg={C_BRAND}>{" ◉ pktscope "}</Text>];
        if (view.get() === "picker") {
          out.push(sep(), <Text fg={C_TITLE}>{"pick an interface to capture on"}</Text>);
          return out;
        }

        const st = status.get();
        const s = stats.get();
        const names = st.ifaces.map((i) => i.name).join(",");
        out.push(sep(), <Text bold fg={C_TITLE}>{names}</Text>);
        if (scope) out.push(<Text fg={C_DIM}>{` · ${scope}`}</Text>);

        out.push(
          sep(),
          <Cap n="1" />,
          <Text bold fg={C_TITLE}>{` ${s.total}`}</Text>,
          <Text fg={C_DIM}>{" pkts "}</Text>,
          <Text fg={C_RX}>{`▼${s.rx}`}</Text>,
          <Text fg={C_DIM}>{" "}</Text>,
          <Text fg={C_TX}>{`▲${s.total - s.rx}`}</Text>,
          <Text fg={C_DIM}>{` · ${fmtBytes(s.bytes)}`}</Text>,
        );

        const kinds = Object.entries(s.kinds);
        if (kinds.length) {
          out.push(sep(), <Text fg={C_ANN}>{kinds.map(([k, v]) => `${k} ${v}`).join(" · ")}</Text>);
        }

        // Echo the filter as it was *understood*, with how many packets pass.
        const q = filter.get();
        if (q) {
          out.push(
            sep(),
            <Text bold fg={C_ANN}>{`⌕ ${q.terms.join(" ")}`}</Text>,
            <Text fg={C_DIM}>{` ${countMatches(q)}/${s.total}`}</Text>,
          );
        }

        // Say so when a pane is hidden or zoomed — otherwise a missing pane
        // reads as a bug rather than a keypress.
        const NAMES = { list: "1 packets", detail: "2 fields", hex: "3 bytes" };
        const hidden = ["list", "detail", "hex"].filter((p) => !panes.get().has(p));
        if (zoom.get()) out.push(sep(), <Text fg={C_DIM}>{"⛶ zoom"}</Text>);
        else if (hidden.length) {
          out.push(sep(), <Text fg={C_DIM}>{`⊟ hidden: ${hidden.map((p) => NAMES[p]).join(", ")}`}</Text>);
        }

        out.push(sep());
        if (st.error) out.push(<Text bold fg={C_BAD}>{`✗ ${st.error}`}</Text>);
        else if (paused.get()) out.push(<Text bold fg={C_TX}>{"⏸ paused"}</Text>);
        else if (!st.running) out.push(<Text fg={C_DIM}>{"⏹ stopped"}</Text>);
        else out.push(<Text bold fg={C_RX}>{follow.get() ? "● live" : "● live ↧"}</Text>);
        return out;
      }}
    </Text>
  </Box>
);
