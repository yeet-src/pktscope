/* Capture session state. Owns the packet ring and the live BPF session;
 * exposes signals the UI reads. Packets accumulate in a plain array — a
 * ring-buffer event must never touch a signal directly (that would re-render
 * per packet); a 150 ms window timer publishes `tick` instead.
 */
import { signal } from "yeet:tui";

import { startScope } from "@/probes/tap.js";
import { summarize } from "@/lib/proto.js";

const CAP = 4000;
const TRIM = 512;
const PUBLISH_MS = 150;

export const pkts = []; // the ring; renders subscribe via `tick`
export const tick = signal(0);
export const sel = signal(0); // selected index into pkts
export const follow = signal(true);
export const paused = signal(false);
export const status = signal({ running: false, ifaces: [], error: null, blob: null });
export const stats = signal({ total: 0, rx: 0, bytes: 0, kinds: {} });

let session = null;
let timer = null;
let dirty = false;
let seq = 0;
let t0 = 0;
const counters = { total: 0, rx: 0, bytes: 0, kinds: {} };

export const startTs = () => t0;
export const current = () => (pkts.length ? pkts[Math.min(sel.get(), pkts.length - 1)] : null);

function onPacket(p) {
  if (paused.get()) return;
  if (!t0) t0 = p.ts;
  counters.total++;
  if (!p.dir) counters.rx++;
  counters.bytes += Math.max(0, p.length - p.payoff);

  p.no = ++seq;
  p.sum = summarize(p);
  if (p.sum.kind) counters.kinds[p.sum.kind] = (counters.kinds[p.sum.kind] ?? 0) + 1;

  pkts.push(p);
  if (pkts.length > CAP) {
    pkts.splice(0, TRIM);
    sel.set(Math.max(0, sel.get() - TRIM));
  }
  dirty = true;
}

export async function start(ifaces, opts = {}) {
  await stop();
  clear();
  status.set({ running: true, ifaces, error: null, blob: null });

  try {
    session = await startScope({ ifaces, ...opts }, onPacket);
  } catch (e) {
    status.set({ running: false, ifaces, error: String(e?.message ?? e), blob: null });
    return;
  }
  status.set({ running: true, ifaces, error: null, blob: session.id });

  timer = setInterval(() => {
    if (!dirty) return;
    dirty = false;
    if (follow.get() && pkts.length) sel.set(pkts.length - 1);
    stats.set({ ...counters, kinds: { ...counters.kinds } });
    tick.update((n) => n + 1);
  }, PUBLISH_MS);
}

export async function stop() {
  if (timer) clearInterval(timer);
  timer = null;
  const s = session;
  session = null;
  if (s) {
    try {
      await s.stop();
    } catch {}
  }
  status.set({ ...status.get(), running: false });
}

export function clear() {
  pkts.length = 0;
  seq = 0;
  t0 = 0;
  dirty = false;
  Object.assign(counters, { total: 0, rx: 0, bytes: 0, kinds: {} });
  stats.set({ total: 0, rx: 0, bytes: 0, kinds: {} });
  sel.set(0);
  follow.set(true);
  tick.update((n) => n + 1);
}
