// Drive the page in headless Chrome over the DevTools protocol.
//
//   node web/drive.mjs <debug-port> <page-url> <output-prefix> [phase ...]
//
// Streams the page's transcript as it runs. At the verdict it saves
// <prefix>.png (the whole page) and <prefix>.json (the result panel's text and
// links). Then runs each further phase in order, in the same page load, saving
// <prefix>-<n>-<phase>.*, and exits 0 only if every phase passed:
//
//   again    "Verify again": must verify again. Repeated runs in one page are
//            where the double-initThreadPool panic hid, and where unfreed
//            verifiers piled up against the 4 GB wasm cap.
//   walk     "Is a block in this chain" on a block about 300 below the tip:
//            must answer IN CHAIN.
//   tamper   "Reject a tampered proof": must end FAILED, not UNREADABLE, since
//            the amber half is reserved for bytes that never parsed.
//
// No dependencies: node 22+ has a global WebSocket.
import { writeFileSync } from "node:fs";

const [port, url, out] = [Number(process.argv[2]), process.argv[3], process.argv[4]];
const PHASES = ["verify", ...process.argv.slice(5)];
if (!port || !url || !out || PHASES.some((p) => !["verify", "again", "walk", "tamper"].includes(p))) {
  console.error("usage: node web/drive.mjs <debug-port> <page-url> <output-prefix> " +
                "[again|walk|tamper ...]");
  process.exit(2);
}

let target = null;
for (let i = 0; i < 60 && !target; i++) {
  try {
    const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    target = pages.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
  } catch {}
  if (!target) await new Promise((r) => setTimeout(r, 500));
}
if (!target) { console.error("no debuggable page"); process.exit(2); }

const ws = new WebSocket(target.webSocketDebuggerUrl);
let seq = 0;
const pending = new Map();
const call = (method, params = {}) => new Promise((resolve) => {
  pending.set(++seq, resolve);
  ws.send(JSON.stringify({ id: seq, method, params }));
});
const ts = () => new Date().toTimeString().slice(0, 8);

async function capture(suffix, verdict) {
  await new Promise((r) => setTimeout(r, 1500));        // let the stamp settle
  const shot = await call("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
  writeFileSync(`${out}${suffix}.png`, Buffer.from(shot.result.data, "base64"));
  const panel = await call("Runtime.evaluate", { returnByValue: true, expression: `(() => {
    const stage = document.getElementById("stage");
    return { text: stage.innerText,
             links: [...stage.querySelectorAll("a")].map((a) => ({ text: a.innerText,
               href: a.href, target: a.target, rel: a.rel })) };
  })()` });
  writeFileSync(`${out}${suffix}.json`, JSON.stringify({ verdict, ...panel.result.result.value }, null, 1));
  console.log(`${ts()} [drive] ${verdict}: wrote ${out}${suffix}.png and .json`);
}

// Matched against the page's own transcript words, so a verdict is never
// inferred from anything but what the page printed.
const NOT_VERIFIED = /^\[jtm\] (FAILED|OUT OF DATE|UNREADABLE|worker error|this device cannot)/;
const TAMPER_MISSED = /^\[jtm\] (ALARM|OUT OF DATE|UNREADABLE|worker error)/;
const WALK_MISSED = /^\[jtm\] (NOT SHOWN|WALK FAILED|worker error)/;
let phase = 0;
let busy = false;

// Start whichever phase comes next, or finish if none does.
async function advance() {
  phase += 1;
  const next = PHASES[phase];
  if (!next) process.exit(0);
  if (next === "walk") {
    const asked = await call("Runtime.evaluate", { returnByValue: true, expression: `(() => {
      const input = document.getElementById("walkh");
      if (!input) return null;
      const target = Math.max(Number(input.min), Number(input.max) - 299);
      input.value = target;
      document.getElementById("walkgo").click();
      return target;
    })()` });
    const target = asked.result.result.value;
    if (target === null) {
      console.log(`${ts()} [drive] no walk form on the result`);
      process.exit(1);
    }
    console.log(`${ts()} [drive] asked whether block ${target} is in the chain`);
  } else {
    const id = next === "again" ? "go" : "tamper";
    await call("Runtime.evaluate", { expression: `document.getElementById("${id}").click()` });
    console.log(`${ts()} [drive] clicked "${next === "again" ? "Verify again" : "Reject a tampered proof"}"`);
  }
}

async function onLine(text) {
  if (busy) return;
  const now = PHASES[phase];
  let verdict = null, pass = false, suffix = phase === 0 ? "" : `-${phase}-${now}`;
  if (now === "verify" || now === "again") {
    if (/^\[jtm\] VERIFIED /.test(text)) { verdict = "verified"; pass = true; }
    else if (NOT_VERIFIED.test(text)) verdict = "not verified";
  } else if (now === "walk") {
    if (/^\[jtm\] IN CHAIN: /.test(text)) { verdict = "walk reached the block"; pass = true; }
    else if (WALK_MISSED.test(text)) verdict = "walk did not reach the block";
  } else if (/^\[jtm\] FAILED: /.test(text)) {
    verdict = "tampered proof rejected"; pass = true;
  } else if (TAMPER_MISSED.test(text)) {
    verdict = "tampered proof NOT reported as a failure";
  }
  if (!verdict) return;
  busy = true;
  await capture(suffix, verdict);
  if (!pass) process.exit(1);
  busy = false;
  await advance();
}

ws.onopen = async () => {
  await call("Runtime.enable");
  await call("Log.enable");
  await call("Page.enable");
  // A desktop viewport: the page refuses to start on anything phone-shaped.
  await call("Emulation.setDeviceMetricsOverride",
             { width: 1400, height: 1700, deviceScaleFactor: 1, mobile: false });
  await call("Page.navigate", { url });
};

ws.onmessage = (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
  if (m.method === "Runtime.consoleAPICalled") {
    const text = m.params.args.map((a) => a.value ?? a.description ?? "").join(" ");
    console.log(`${ts()} ${text}`);
    onLine(text);
  }
  if (m.method === "Log.entryAdded" && m.params.entry.level === "error")
    console.log(`${ts()} [browser] ${m.params.entry.text} ${m.params.entry.url || ""}`);
  if (m.method === "Runtime.exceptionThrown")
    console.log(`${ts()} [exception] ${m.params.exceptionDetails.exception?.description
      || m.params.exceptionDetails.text}`);
};
ws.onclose = () => { console.log(`${ts()} [drive] devtools connection closed`); process.exit(2); };
