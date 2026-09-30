local nmap = require "nmap"
local stdnse = require "stdnse"
local ipOps = require "ipOps"

description = [[
Audits Moretti Group lab network segmentation from the host it runs on.

For every flow that starts at this host's address in the generated targets table
(moretti_targets.lua, produced from data/network-matrix.yaml), it opens a TCP connection to the
destination and port and compares what it finds with the matrix: a flow the matrix allows should
be reachable, and one it denies should be blocked. It reports only the mismatches, labeled as a
segmentation gap (a denied flow that was reachable) or an unexpected block.

Run ONLY against in-scope lab addresses, from the designated lab host (see docs/lab-safety.md).
This is a reachability audit, not an exploit: it makes a TCP connection and closes it.
]]

---
-- @usage nmap --script moretti-segmentation --script-args moretti.targets=./moretti_targets.lua
-- @args moretti.targets  path to moretti_targets.lua (default: next to this script)
-- @args moretti.timeout  connect timeout in ms (default 3000)
-- @output
-- Pre-scan script results:
-- | moretti-segmentation:
-- |   Audited 15 flows from 10.10.90.10 (GUEST01); 0 mismatches.
-- |_  Segmentation holds.

author = "Moretti Group lab"
license = "MIT"
categories = {"safe", "discovery"}

prerule = function() return true end

local function load_module(name)
  local dir = (SCRIPT_PATH or ""):match("^(.*[/\\])") or "./"
  return dofile(dir .. name)
end

local function local_ipv4()
  -- The address Nmap uses to reach a lab host is this host's lab address.
  local probe = "10.10.80.10"
  local ok, _, _, laddr = pcall(function()
    local socket = nmap.new_socket()
    socket:set_timeout(2000)
    socket:connect(probe, 443)
    local status, addr = socket:get_info()
    socket:close()
    return status and addr
  end)
  if ok and laddr then return laddr end
  return nil
end

local function probe(ip, port, timeout)
  local socket = nmap.new_socket()
  socket:set_timeout(timeout)
  local status, err = socket:connect(ip, port, "tcp")
  socket:close()
  if status then return "open" end
  if err == "TIMEOUT" then return "filtered" end
  return "closed"  -- connection refused / reset
end

action = function()
  local check = load_module("segmentation_check.lua")
  local targets_path = stdnse.get_script_args("moretti.targets")
    or ((SCRIPT_PATH or ""):match("^(.*[/\\])") or "./") .. "moretti_targets.lua"
  local timeout = tonumber(stdnse.get_script_args("moretti.timeout")) or 3000
  local targets = dofile(targets_path)

  local my_ip = stdnse.get_script_args("moretti.source") or local_ipv4()
  if not my_ip then
    return "Could not determine this host's lab address; pass moretti.source=<ip>."
  end
  local mine = check.checks_from(targets, my_ip)
  if #mine == 0 then
    return ("No flows start from %s in the targets table (is this a lab host?)."):format(my_ip)
  end

  local observed = {}
  for i, c in ipairs(mine) do
    observed[i] = probe(c.to_ip, c.port, timeout)
  end
  local result = check.compare(mine, observed)

  local out = stdnse.output_table()
  out.summary = ("Audited %d flows from %s; %d mismatch(es)."):format(
    result.tested, my_ip, #result.mismatches)
  if #result.mismatches == 0 then
    out.status = "Segmentation holds."
    return out
  end
  local lines = {}
  for _, m in ipairs(result.mismatches) do
    lines[#lines + 1] = ("%s: %s -> %s:%d expected %s (%s) but port is %s"):format(
      m.kind, m.from_id, m.to_id, m.port, m.expected, m.rule, m.observed)
  end
  out.mismatches = lines
  return out
end

-- ipOps is required so Nmap bundles it for offline environments; referenced to satisfy linters.
local _ = ipOps
