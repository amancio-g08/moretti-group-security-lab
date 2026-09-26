/* SYNTHETIC TEST (no Packet Tracer involved).
   Run: node project-01-network/tools/tests/mock_ptbuilder_cli.test.js
   Exits with code 1 if the build script would apply any line in the wrong CLI context.

   Models the Packet Tracer CLI behaviour observed on CORE-SW01 via the API:
   inside a sub-mode, a context change ("interface ...", "vlan ...", "line ...") is rejected. */
const fs = require("fs");
const src = fs.readFileSync(process.argv[2] || __dirname + "/../../packet-tracer/build-topology.js", "utf8").replace(/\n/g, "");
const CTX = /^(interface|vlan |line |ip access-list|ip dhcp pool|policy-map|router )/;
function makeDevice(name, store) {
  let ctx = null; /* null = global config */
  store[name] = { global: [], ctx: {} , rejected: 0};
  const st = store[name];
  return {
    enterCommand(cmd, mode) {
      if (mode === "global") ctx = null;
      if (mode === "enable") return;
      const top = cmd.charAt(0) !== " ";
      const c = cmd.trim();
      if (c === "!" ) return;
      if (c === "exit" || c === "end") { ctx = null; return; }
      if (top && ctx !== null) { st.rejected++; return; }          /* context change rejected in sub-mode */
      if (top && CTX.test(c)) { ctx = c; st.ctx[ctx] = st.ctx[ctx] || []; return; }
      if (top) { st.global.push(c); return; }
      if (ctx === null) { st.rejected++; return; }
      st.ctx[ctx].push(c);
    },
    skipBoot() {}, setPower() {}, getPower() { return true; },
  };
}
function run(useOld) {
  const store = {}; const devs = {};
  const g = {
    getDevices: () => [], addDevice: () => true, addModule: () => true, addLink: () => true, configurePcIp: () => {},
    configureIosDevice: (n, cmds) => { const d = devs[n]; d.enterCommand("!", "global"); for (const c of cmds.split("\n")) d.enterCommand(c, ""); },
    ipc: { network: () => ({ getDevice: (n) => (devs[n] = devs[n] || makeDevice(n, store)) }), appWindow: () => ({ showMessageBox() {} }) },
  };
  let s = src.replace('var ENABLE_SECRET = "";', 'var ENABLE_SECRET = "x";').replace('var ADMIN_SECRET = "";', 'var ADMIN_SECRET = "x";');
  if (useOld) s = s.replace(/sendConfig\(name, commands\);/, 'configureIosDevice(name, commands.join("\\n"));');
  new Function(...Object.keys(g), s)(...Object.values(g));
  return store;
}
function expected(name, commands) {
  const exp = {}; let ctx = null;
  for (const l of commands) { const c = l.trim(); if (!c) continue;
    if (l.charAt(0) !== " ") { if (c === "exit") { ctx = null; continue; } ctx = CTX.test(c) ? c : null; if (ctx) exp[ctx] = exp[ctx] || []; continue; }
    if (ctx) exp[ctx].push(c); }
  return exp;
}
const CONFIGS = new Function(src.match(/var CONFIGS = [\s\S]*?\};(?=var CORE_ACLS)/)[0] + "return CONFIGS;")();
for (const [label, old] of [["OLD method (PTBuilder configureIosDevice)", true], ["NEW method (sendConfig)", false]]) {
  const store = run(old);
  let wrong = 0, total = 0;
  for (const [dev, c] of Object.entries(CONFIGS)) {
    const exp = expected(dev, c.commands);
    for (const [ctx, lines] of Object.entries(exp)) { total++;
      if (JSON.stringify((store[dev].ctx[ctx] || [])) !== JSON.stringify(lines)) wrong++; }
  }
  const v10 = (store["CORE-SW01"].ctx["interface Vlan10"] || []).join(" | ");
  console.log(`${label}: contexts correct ${total - wrong}/${total}; rejected commands: ${Object.values(store).reduce((a, d) => a + d.rejected, 0)}`);
  console.log(`   CORE-SW01 interface Vlan10 -> ${v10}`);
}
const final = run(false);
let bad = 0;
for (const [dev, c] of Object.entries(CONFIGS)) {
  for (const [ctx, lines] of Object.entries(expected(dev, c.commands))) {
    if (JSON.stringify(final[dev].ctx[ctx] || []) !== JSON.stringify(lines)) bad++;
  }
}
process.exit(bad ? 1 : 0);
