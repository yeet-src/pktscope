// A raised key-cap: the key glyph in bold gold on a tile a shade lighter
// than the rail. Used for the footer hints and for the pane badges, so a
// pane's number reads as "press this to toggle me".
import { Text } from "yeet:tui";

import { C_ANN, C_CAP } from "@/lib/format.js";

export default ({ n }) => (
  <Text bg={C_CAP} bold fg={C_ANN}>{` ${n} `}</Text>
);
