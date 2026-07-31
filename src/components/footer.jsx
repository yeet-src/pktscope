// Key-hint rail, context-sensitive: the hints follow the focused pane. Each
// shortcut is a raised key-cap (bold on a lighter tile) + a dimmed label.
import { Box, Text } from "yeet:tui";

import { C_ANN, C_CAP, C_DIM, C_RAIL } from "@/lib/format.js";

const hint = (keys, label) => [
  <Text bg={C_CAP} bold fg={C_ANN}>{` ${keys} `}</Text>,
  <Text fg={C_DIM}>{` ${label}  `}</Text>,
];

const HINTS = {
  picker: [["↑↓", "select"], ["→/⏎", "capture"], ["q", "quit"]],
  list: [
    ["↑↓", "packet"], ["→", "fields"], ["←", "interfaces"], ["p", "pause"],
    ["f", "follow"], ["/", "filter"], ["c", "clear"], ["z", "zoom"],
    ["+/-", "resize"], ["1·2·3", "panes"], ["q", "quit"],
  ],
  detail: [
    ["↑↓", "field"], ["→", "open"], ["←", "back"], ["⏎", "fold"],
    ["z", "zoom"], ["+/-", "resize"], ["1·2·3", "panes"], ["q", "quit"],
  ],
  search: [
    ["⏎", "apply"], ["esc", "cancel"],
    ["", "tls · http2 · dns · port 443 · host 10.0.0.1 · syn · rx · data · len>500 · !ack"],
  ],
};

export default ({ mode, size }) => (
  <Box height="1" direction="row" bg={C_RAIL}>
    <Text break="none">
      {() => {
        // Hints are listed most-useful-first, so a narrow rail simply keeps
        // the prefix that fits instead of clipping a cap mid-glyph.
        const all = HINTS[mode.get()] ?? HINTS.list;
        const cols = size.get().cols;
        const out = [" "];
        let used = 1;
        for (const [k, l] of all) {
          const cost = k ? k.length + l.length + 5 : l.length + 1;
          if (used + cost > cols) break;
          used += cost;
          out.push(...(k ? hint(k, l) : [<Text fg={C_DIM}>{` ${l}`}</Text>]));
        }
        return out;
      }}
    </Text>
  </Box>
);
