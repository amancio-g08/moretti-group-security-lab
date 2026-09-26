// =====================================================================================
// Moretti Group network - Packet Tracer build script (FICTITIOUS LAB)
//
// GENERATED FILE - do not edit. Source: project-01-network/topology.yaml, data/*.yaml,
// project-01-network/configs/. Regenerate with:
//     python3 project-01-network/tools/build_ptbuilder_script.py --write
//
// Requires the PTBuilder extension (https://github.com/kimmknight/PTBuilder).
// Run in Packet Tracer: Extensions -> Builder Code Editor -> paste this file -> Run.
// See project-01-network/documentation/build-guide.md (automated build).
// =====================================================================================

// ---- 1. Credentials: fill in ONLY inside Packet Tracer. Never commit these values. ----
var ENABLE_SECRET = "";
var ADMIN_SECRET = "";

// ---- 2. What to run. Recommended: run once as-is, test (validation plan stage 1), then
//         set everything to false except RUN_CORE_ACLS and run again. ----
var RUN_TOPOLOGY = true;       // create devices and cables
var RUN_HOST_IP = true;        // IP settings of PCs and servers
var RUN_DEVICE_CONFIG = true;  // configure switches, firewall and routers
var RUN_CORE_ACLS = false;     // inter-VLAN ACLs on CORE-SW01 (after stage 1 tests pass)

// ------------------------------------------------------------------------------------
var DEVICES = __DEVICES__;
var LINKS = __LINKS__;
var HOSTS = __HOSTS__;
var CONFIGS = __CONFIGS__;
var CORE_ACLS = __CORE_ACLS__;

var report = { ok: [], failed: [] };

function done(step, detail) { report.ok.push(step + (detail ? " (" + detail + ")" : "")); }
function fail(step, error) { report.failed.push(step + ": " + error); }

function deviceExists(name) {
    try { return getDevices().indexOf(name) !== -1; } catch (e) { return false; }
}

// The exact slot name of the 3650 power supply is not documented; try the likely ones.
function addPowerSupply(name) {
    var slots = ["1", "0", "2", "0/1", "0/0", "1/0", "PS1", "PS-A"];
    for (var i = 0; i < slots.length; i++) {
        try {
            if (addModule(name, slots[i], "AC-POWER-SUPPLY")) {
                var device = ipc.network().getDevice(name);
                device.setPower(true);
                device.skipBoot();
                return slots[i];
            }
        } catch (e) { /* try the next slot */ }
    }
    return null;
}

function credentialCommands(kind) {
    if (kind === "ios") {
        return ["enable secret " + ENABLE_SECRET,
                "username netadmin privilege 15 secret " + ADMIN_SECRET];
    }
    if (kind === "asa") {
        return ["enable password " + ENABLE_SECRET,
                "username netadmin password " + ADMIN_SECRET + " privilege 15"];
    }
    return [];
}

function keyCommand(kind) {
    if (kind === "ios") { return ["crypto key generate rsa general-keys modulus 2048"]; }
    if (kind === "asa") { return ["crypto key generate rsa modulus 2048"]; }
    return [];
}

function buildTopology() {
    for (var i = 0; i < DEVICES.length; i++) {
        var d = DEVICES[i];
        if (deviceExists(d.name)) { done("device " + d.name, "already present"); continue; }
        try {
            if (!addDevice(d.name, d.model, d.x, d.y)) { fail("device " + d.name, "addDevice returned false"); continue; }
            done("device " + d.name);
            if (d.power_supply) {
                var slot = addPowerSupply(d.name);
                if (slot === null) { fail("power supply " + d.name, "add AC-POWER-SUPPLY manually (Physical tab)"); }
                else { done("power supply " + d.name, "slot " + slot); }
            }
        } catch (e) { fail("device " + d.name, e); }
    }
    for (var j = 0; j < LINKS.length; j++) {
        var l = LINKS[j];
        var label = "link " + l[0] + " " + l[1] + " <-> " + l[2] + " " + l[3];
        try {
            if (addLink(l[0], l[1], l[2], l[3], l[4])) { done(label); }
            else { fail(label, "addLink returned false (already connected, or interface name not found)"); }
        } catch (e) { fail(label, e); }
    }
}

function configureHosts() {
    for (var i = 0; i < HOSTS.length; i++) {
        var h = HOSTS[i];
        try {
            configurePcIp(h.name, h.dhcp, h.ip || undefined, h.mask || undefined,
                          h.gateway || undefined, h.dns || undefined);
            done("host IP " + h.name, h.dhcp ? "DHCP" : h.ip);
        } catch (e) { fail("host IP " + h.name, e); }
    }
}

function configureDevices() {
    for (var name in CONFIGS) {
        var c = CONFIGS[name];
        var commands = credentialCommands(c.credentials)
            .concat(c.commands)
            .concat(keyCommand(c.credentials))
            .concat(["end"]);
        try {
            try { ipc.network().getDevice(name).skipBoot(); } catch (e) { /* not all devices boot */ }
            configureIosDevice(name, commands.join("\n"));
            done("config " + name, commands.length + " commands sent");
        } catch (e) { fail("config " + name, e); }
    }
}

function applyCoreAcls() {
    try {
        configureIosDevice("CORE-SW01", CORE_ACLS.concat(["end"]).join("\n"));
        done("core ACLs", CORE_ACLS.length + " commands sent");
    } catch (e) { fail("core ACLs", e); }
}

function showReport() {
    var text = "OK: " + report.ok.length + "   FAILED: " + report.failed.length;
    var detail = report.failed.length
        ? "Failed steps (send this list back for fixing):\n" + report.failed.join("\n")
        : "All steps completed. Next: configure server services (build guide) and run the validation plan.";
    try {
        ipc.appWindow().showMessageBox("Moretti Group build" + " ".repeat(80), text, detail, 3, 0x00000400, 0x00000400, 0x00000400);
    } catch (e) { /* message box unavailable */ }
}

// ------------------------------------------------------------------------------------
if ((RUN_DEVICE_CONFIG || RUN_CORE_ACLS) && (!ENABLE_SECRET || !ADMIN_SECRET)) {
    throw new Error("Set ENABLE_SECRET and ADMIN_SECRET at the top of the script before configuring devices.");
}
if (RUN_TOPOLOGY) { buildTopology(); }
if (RUN_HOST_IP) { configureHosts(); }
if (RUN_DEVICE_CONFIG) { configureDevices(); }
if (RUN_CORE_ACLS) { applyCoreAcls(); }
showReport();
