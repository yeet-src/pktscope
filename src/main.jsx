/* pktscope — a Wireshark-style terminal packet analyzer, on any interface
 * including raw-IP tunnel devices (tunl0, ipip, gre), where tcpdump-era
 * assumptions about an Ethernet header break.
 *
 *   yeet run . --tty                          # interface picker
 *   yeet run . --tty -- --iface tunl0         # capture immediately
 *   yeet run . --tty -- --iface eth0 --port 443 --proto tcp
 *
 * Three panes, Wireshark-shaped: a live packet list (rows colored by what
 * the payload was identified as — TLS records with SNI, HTTP/1 with its
 * headers, HTTP/2 preface + frames, DNS), a folding protocol detail tree,
 * and a hex dump colored by section. Selecting a field in the tree
 * highlights exactly the bytes it decodes in the hex pane.
 *
 * ←/→ are back/forward everywhere: → drills in (pick an interface, step into
 * the fields pane, open a folded section, descend to its fields) and ← climbs
 * back out (field → section → fold it → the packet list → the interfaces).
 *
 * Keys — picker: ↑↓ select, ⏎/→ capture. List: ↑↓/jk packet, →/⇥ fields,
 * f follow tail, p pause, / filter, c clear, 1·2·3 toggle panes, z zoom,
 * +/- resize, ←/esc interfaces, q quit. Fields: ↑↓ field, → open/descend,
 * ← fold/back, ⏎ toggle fold. Mouse: wheel scrolls the pane under the
 * cursor (including the bytes pane), click selects, and dragging a pane
 * divider resizes it.
 *
 * Layout: probes/ (BPF-aware) → signals → components/ (pure UI); lib/ is
 * pure parsing and formatting. Build with `make`, which compiles
 * src/bpf/pktscope.bpf.c → bin/probe.bpf.o and bundles this entry.
 */
import { Box, computed, mount, signal } from "yeet:tui";

import * as cap from "@/probes/capture.js";
import { findIfaces, ifaces } from "@/probes/ifaces.js";
import { applyFilter, compileFilter } from "@/lib/filter.js";
import { buildTree, flatRows } from "@/lib/proto.js";
import { clamp } from "@/lib/format.js";
import DetailTree, { detailView } from "@/components/detailtree.jsx";
import Footer from "@/components/footer.jsx";
import HexPane from "@/components/hexpane.jsx";
import Picker, { selectable } from "@/components/picker.jsx";
import PktList, { listView } from "@/components/pktlist.jsx";
import TitleBar from "@/components/titlebar.jsx";

/* --- args --- */

const args = yeet.args ?? {};
const argIface = args.iface ?? args.i;
const argPort = Number(args.port ?? 0) >>> 0 & 0xffff;
const argProto = String(args.proto ?? "").toLowerCase() === "tcp" ? 6 : String(args.proto ?? "").toLowerCase() === "udp" ? 17 : 0;
const scopeStr = [argPort ? `port ${argPort}` : null, argProto === 6 ? "tcp" : argProto === 17 ? "udp" : null]
  .filter(Boolean)
  .join(" · ");

/* --- UI state --- */

const view = signal("picker"); // "picker" | "capture"
const focus = signal("list"); // "list" | "detail"
const filter = signal(null); // applied display filter (null = off)
const searching = signal(false); // filter input is capturing keys
const pSel = signal(0); // picker row
const dSel = signal(0); // detail-tree row
const collapsed = signal(new Set()); // folded section ids

// Pane geometry: which panes are shown, whether the focused one is zoomed to
// the full body, and the rows added to the fields/bytes panes by +/-.
const panes = signal(new Set(["list", "detail", "hex"]));
const zoom = signal(false);
const detDelta = signal(0);
const hexDelta = signal(0);

// Manual bytes-pane scroll (rows), applied on top of the highlight
// auto-centering; selection moves reset it. Bounded by the most rows a
// full capture can span (CAP bytes at 8 per row on a narrow terminal).
const HEX_SCROLL_MAX = 192;
const hexScroll = signal(0);

const mode = computed(() =>
  view.get() === "picker" ? "picker" : searching.get() ? "search" : focus.get(),
);

// The filter text compiles once per edit, not once per rendered row.
const query = computed(() => compileFilter(filter.get()));

// The byte range the hex pane highlights: the detail row under the cursor,
// while the detail pane is focused.
const selRange = computed(() => {
  if (view.get() !== "capture" || focus.get() !== "detail") return null;
  cap.tick.get();
  const p = cap.current();
  if (!p) return null;
  const rows = flatRows((p.tree ??= buildTree(p)), collapsed.get());
  return rows[clamp(0, dSel.get(), rows.length - 1)]?.range ?? null;
});

let layout = { body: 20, listH: 12, detH: 8, hexH: 6, cols: 80, rows: 24 };

const MIN_PANE = 3;

// Pane heights. Reads the pane signals, so it belongs inside a render thunk —
// toggling, zooming or resizing reflows exactly like a terminal resize does.
function layoutFor({ rows, cols }) {
  const body = Math.max(MIN_PANE, rows - 2);
  const shown = panes.get();
  const geom = (listH, detH, hexH) => ({ body, listH, detH, hexH, cols, rows });

  // Zoom gives the whole body to the focused pane (the bytes pane never takes
  // focus, so it's never the zoom target).
  if (zoom.get()) return focus.get() === "detail" ? geom(0, body, 0) : geom(body, 0, 0);

  const showList = shown.has("list");
  let detH = shown.has("detail") ? clamp(MIN_PANE, Math.floor(body * 0.3) + detDelta.get(), body - (showList ? MIN_PANE : 0)) : 0;
  let hexH = shown.has("hex") ? clamp(MIN_PANE, Math.floor(body * 0.28) + hexDelta.get(), body - (showList ? MIN_PANE : 0)) : 0;

  if (!showList) {
    // Two panes share the body: the fields pane keeps its size, the bytes
    // pane absorbs the rest (or one of them takes everything).
    if (detH && hexH) return geom(0, detH, body - detH);
    return geom(0, detH ? body : 0, hexH ? body : 0);
  }

  // The list absorbs the remainder; when that would starve it, claw rows back
  // from the bytes pane first, then the fields pane.
  let listH = body - detH - hexH;
  if (listH < MIN_PANE) {
    const over = MIN_PANE - listH;
    const fromHex = Math.min(over, Math.max(0, hexH - MIN_PANE));
    hexH -= fromHex;
    detH -= Math.min(over - fromHex, Math.max(0, detH - MIN_PANE));
    listH = Math.max(1, body - detH - hexH);
  }
  return geom(listH, detH, hexH);
}

/* --- actions --- */

async function startCapture(rows) {
  view.set("capture");
  focus.set("list");
  dSel.set(0);
  hexScroll.set(0);
  await cap.start(rows, { port: argPort, proto: argProto });
}

function moveList(delta) {
  const rows = applyFilter(cap.pkts, query.get());
  if (!rows.length) return;
  const cur = cap.pkts[Math.min(cap.sel.get(), cap.pkts.length - 1)];
  let pos = rows.indexOf(cur);
  if (pos < 0) pos = rows.length - 1;
  const np = clamp(0, pos + delta, rows.length - 1);
  cap.sel.set(cap.pkts.indexOf(rows[np]));
  hexScroll.set(0);
  // Follow re-engages only when parked on the literal newest packet —
  // "last row of a filtered list" isn't the tail of the capture.
  cap.follow.set(rows[np] === cap.pkts[cap.pkts.length - 1]);
}

const detailRows = () => {
  const p = cap.current();
  return p ? flatRows((p.tree ??= buildTree(p)), collapsed.get()) : [];
};

function moveDetail(delta) {
  const n = detailRows().length;
  if (n) dSel.set(clamp(0, clamp(0, dSel.get(), n - 1) + delta, n - 1));
  hexScroll.set(0);
}

const curDetailRow = () => {
  const rows = detailRows();
  return rows[clamp(0, dSel.get(), rows.length - 1)] ?? null;
};

/* ← / → are drill-down: → opens a folded section, then descends into its
 * fields; ← climbs from a field to its section header, folds an open
 * section, and from an already-folded one steps back out to the packet list.
 */
function forward() {
  const r = curDetailRow();
  if (!r) return;
  if (r.sec && !r.open) return setFold(r.id, false);
  if (r.sec) return moveDetail(1); // descend to the first field
}

function back() {
  const r = curDetailRow();
  if (!r) return focus.set("list");
  if (!r.sec) {
    // Climb to this field's section header.
    const rows = detailRows();
    for (let i = clamp(0, dSel.get(), rows.length - 1); i >= 0; i--) {
      if (rows[i].sec) return dSel.set(i);
    }
    return;
  }
  if (r.open) return setFold(r.id, true);
  focus.set("list");
}

function setFold(id, fold) {
  const next = new Set(collapsed.get());
  if (fold) next.add(id);
  else next.delete(id);
  collapsed.set(next);
  const p = cap.current();
  const after = p ? flatRows((p.tree ??= buildTree(p)), next) : [];
  dSel.set(Math.max(0, after.findIndex((x) => x.sec && x.id === id)));
}

function toggleFold() {
  const rows = detailRows();
  const r = rows[clamp(0, dSel.get(), rows.length - 1)];
  if (!r) return;
  const next = new Set(collapsed.get());
  if (next.has(r.id)) next.delete(r.id);
  else next.add(r.id);
  collapsed.set(next);
  // Folding while on a field: park the cursor on its section header.
  const p = cap.current();
  const after = p ? flatRows((p.tree ??= buildTree(p)), next) : [];
  dSel.set(Math.max(0, after.findIndex((x) => x.sec && x.id === r.id)));
}

function togglePane(id) {
  const next = new Set(panes.get());
  if (next.has(id)) {
    if (next.size === 1) return; // never hide the last pane
    next.delete(id);
  } else {
    next.add(id);
  }
  panes.set(next);
  zoom.set(false);
  // Focus can't stay on a pane that just went away.
  if (!next.has("detail") && focus.get() === "detail") focus.set("list");
  if (!next.has("list") && focus.get() === "list" && next.has("detail")) focus.set("detail");
}

// +/- trade rows between the focused pane and its neighbour: the fields pane
// resizes itself, while the list (which absorbs the remainder) trades with
// the bytes pane below it.
function resize(d) {
  zoom.set(false);
  const bump = (sig, delta) => sig.update((v) => clamp(-20, v + delta, 40));
  if (focus.get() === "detail") return bump(detDelta, d);
  if (panes.get().has("hex")) return bump(hexDelta, -d);
  if (panes.get().has("detail")) return bump(detDelta, -d);
}

async function leaveCapture() {
  await cap.stop();
  view.set("picker");
  filter.set(null);
  searching.set(false);
}

function quit() {
  cap.stop();
  setTimeout(() => yeet.exit(), 0);
}

/* --- input --- */

// Ask the terminal to report mouse events; without this the wheel/click/drag
// handlers below are registered but never fire.
tty.enableMouse();

const isUp = (c, k) => c === "ArrowUp" || k === "k";
const isDown = (c, k) => c === "ArrowDown" || k === "j";
const isEnter = (c) => c === "Enter" || c === "Return";

tty.on("keydown", (e) => {
  const c = e.code;
  const k = e.key ?? "";

  if (searching.get()) {
    if (c === "Escape") {
      searching.set(false);
      filter.set(null);
    } else if (isEnter(c)) {
      searching.set(false);
      if (!filter.get()) filter.set(null);
    } else if (c === "Backspace") {
      filter.set((filter.get() ?? "").slice(0, -1));
    } else if (k.length === 1 && !e.ctrlKey && !e.altKey) {
      filter.set((filter.get() ?? "") + k);
    }
    return;
  }

  if (k === "q" || (e.ctrlKey && k === "c")) return quit();

  if (view.get() === "picker") {
    const rows = ifaces.get();
    if (isUp(c, k)) pSel.set(Math.max(0, pSel.get() - 1));
    else if (isDown(c, k)) pSel.set(Math.min(Math.max(0, rows.length - 1), pSel.get() + 1));
    else if (isEnter(c) || c === "ArrowRight" || k === "l") {
      const r = rows[Math.min(pSel.get(), Math.max(0, rows.length - 1))];
      if (r && selectable(r)) startCapture([r]);
    }
    return;
  }

  // Pane management is the same in either pane.
  if (k === "1") return togglePane("list");
  if (k === "2") return togglePane("detail");
  if (k === "3") return togglePane("hex");
  if (k === "z") return zoom.set(!zoom.get());
  if (k === "+" || k === "=") return resize(1);
  if (k === "-" || k === "_") return resize(-1);

  if (focus.get() === "detail") {
    if (isUp(c, k)) moveDetail(-1);
    else if (isDown(c, k)) moveDetail(1);
    else if (c === "PageUp") moveDetail(-(layout.detH - 1));
    else if (c === "PageDown") moveDetail(layout.detH - 1);
    else if (k === "g") moveDetail(-1e9);
    else if (k === "G") moveDetail(1e9);
    else if (c === "ArrowRight" || k === "l") forward();
    else if (c === "ArrowLeft" || k === "h") back();
    else if (isEnter(c) || k === " ") toggleFold();
    else if (c === "Tab" || c === "Escape") {
      focus.set("list");
      zoom.set(false);
    }
    return;
  }

  // list focus
  if (isUp(c, k)) moveList(-1);
  else if (isDown(c, k)) moveList(1);
  else if (c === "PageUp") moveList(-(layout.listH - 1));
  else if (c === "PageDown") moveList(layout.listH - 1);
  else if (k === "g") moveList(-1e9);
  else if (k === "G" || k === "f") {
    cap.follow.set(true);
    moveList(1e9);
  } else if (c === "Tab" || isEnter(c) || c === "ArrowRight" || k === "l") {
    // Stepping into the fields pane un-hides it — otherwise focus lands
    // somewhere invisible.
    if (!panes.get().has("detail")) togglePane("detail");
    focus.set("detail");
  } else if (c === "ArrowLeft" || k === "h") leaveCapture();
  else if (k === "p") cap.paused.set(!cap.paused.get());
  else if (k === "c") {
    cap.clear();
    hexScroll.set(0);
  }
  else if (k === "/") {
    // Fresh query, like `less`/`vim` — appending to whatever was already
    // applied is never what you meant.
    searching.set(true);
    filter.set("");
  } else if (c === "Escape") {
    if (filter.get() !== null) filter.set(null);
    else leaveCapture();
  }
});

// The pane under a screen row, from the live layout. Row 0 is the title
// bar; each pane's header row scrolls with its body.
function paneAt(y) {
  const listEnd = 1 + layout.listH;
  const detEnd = listEnd + layout.detH;
  if (layout.listH && y >= 1 && y < listEnd) return "list";
  if (layout.detH && y >= listEnd && y < detEnd) return "detail";
  if (layout.hexH && y >= detEnd && y < detEnd + layout.hexH) return "hex";
  return null;
}

/* The wheel scrolls whatever is under the cursor, not the focused pane —
 * the list and fields panes by moving their selection, the bytes pane by
 * a manual offset on top of the highlight auto-centering.
 */
tty.on("wheel", (e) => {
  if (!e.deltaY) return;
  const d = e.deltaY > 0 ? 3 : -3;

  if (view.get() === "picker") {
    const n = ifaces.get().length;
    pSel.set(clamp(0, pSel.get() + d, Math.max(0, n - 1)));
    return;
  }

  const pane = paneAt(e.clientY) ?? (focus.get() === "detail" ? "detail" : "list");
  if (pane === "hex") hexScroll.update((v) => clamp(-HEX_SCROLL_MAX, v + d, HEX_SCROLL_MAX));
  else if (pane === "detail") moveDetail(d);
  else moveList(d);
});

/* Mouse. A press on a pane divider (the "── fields" / "── bytes" header row)
 * starts a drag that resizes just the two panes it separates, tmux-style;
 * anywhere else it selects the row under the cursor. Divider rows are the
 * pane headers themselves, which no row mapping claims.
 */
let drag = null;

// Screen row of each divider, or -1 when that pane is hidden.
const dividers = () => ({
  fields: layout.detH ? 1 + layout.listH : -1,
  bytes: layout.hexH ? 1 + layout.listH + layout.detH : -1,
});

tty.on("mousedown", (e) => {
  if (e.button !== 0 || view.get() !== "capture") return;
  const y = e.clientY;
  const div = dividers();

  if (y === div.fields || y === div.bytes) {
    zoom.set(false);
    drag = { which: y === div.fields ? "fields" : "bytes", y0: y, det0: detDelta.get(), hex0: hexDelta.get() };
    return;
  }

  const listRow0 = 2; // title + column header
  const detRow0 = 1 + layout.listH + 1; // + detail pane header

  if (y >= listRow0 && y < 1 + layout.listH) {
    const i = listView.top + (y - listRow0);
    if (i < listView.rows.length) {
      focus.set("list");
      cap.sel.set(cap.pkts.indexOf(listView.rows[i]));
      cap.follow.set(listView.rows[i] === cap.pkts[cap.pkts.length - 1]);
      hexScroll.set(0);
    }
  } else if (y >= detRow0 && y < 1 + layout.listH + layout.detH) {
    const i = detailView.top + (y - detRow0);
    if (i < detailView.rows.length) {
      focus.set("detail");
      dSel.set(i);
      hexScroll.set(0);
    }
  }
});

// Dragging a divider moves only the boundary: the pane above gives rows to
// the pane below and vice versa, leaving the third pane's height alone.
tty.on("mousemove", (e) => {
  if (!drag) return;
  if (e.buttons != null && !(e.buttons & 1)) {
    drag = null;
    return;
  }
  const dy = e.clientY - drag.y0;
  const set = (sig, v) => sig.set(clamp(-20, v, 40));
  if (drag.which === "fields") {
    set(detDelta, drag.det0 - dy);
  } else {
    set(hexDelta, drag.hex0 - dy);
    set(detDelta, drag.det0 + dy);
  }
});

tty.on("mouseup", () => {
  drag = null;
});

/* --- root --- */

const Root = (size) => (
  <Box>
    <TitleBar view={view} filter={query} scope={scopeStr} panes={panes} zoom={zoom} />
    <Box height="1fr" overflow="hidden">
      {() => {
        const L = (layout = layoutFor(size.get()));
        if (view.get() === "picker") return <Picker sel={pSel} height={L.body} width={L.cols} />;
        const out = [];
        if (L.listH) {
          out.push(
            <Box height={`${L.listH}`} overflow="hidden">
              <PktList height={L.listH} width={L.cols} filter={query} focus={focus} />
            </Box>,
          );
        }
        if (L.detH) {
          out.push(
            <Box height={`${L.detH}`} overflow="hidden">
              <DetailTree height={L.detH} width={L.cols} focus={focus} dSel={dSel} collapsed={collapsed} />
            </Box>,
          );
        }
        if (L.hexH) {
          out.push(
            <Box height={`${L.hexH}`} overflow="hidden">
              <HexPane height={L.hexH} width={L.cols} selRange={selRange} scroll={hexScroll} />
            </Box>,
          );
        }
        return out;
      }}
    </Box>
    <Footer mode={mode} size={size} />
  </Box>
);

if (argIface != null) {
  try {
    const targets = await findIfaces(argIface);
    startCapture(targets);
  } catch (e) {
    cap.status.set({ running: false, ifaces: [], error: String(e?.message ?? e), blob: null });
    view.set("capture");
  }
}

mount(Root);
await new Promise(() => {}); // keep the script alive; the TUI owns the screen
