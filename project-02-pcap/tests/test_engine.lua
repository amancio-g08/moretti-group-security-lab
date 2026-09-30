-- Unit tests of the policy engine, against the policy generated from data/.
-- Run from the repository root with any Lua 5.2-5.4 interpreter:
--   lua5.4 project-02-pcap/tests/test_engine.lua

local dir = "project-02-pcap/wireshark/"
local engine = dofile(dir .. "policy_engine.lua")
local policy = dofile(dir .. "moretti_policy.lua")

local failures, count = 0, 0
local function check(name, got, want)
  count = count + 1
  if got ~= want then
    failures = failures + 1
    print(string.format("FAIL %s: got %s, want %s", name, tostring(got), tostring(want)))
  end
end

local aws = engine.new(policy, "aws")
local pt = engine.new(policy, "pt")

-- Addresses and ranges
check("parse", engine.to_number("10.10.20.10"), 168432650)
check("parse rejects octet > 255", engine.to_number("10.10.20.300"), nil)
check("parse rejects text", engine.to_number("not-an-ip"), nil)
check("private 172.16/12 upper edge", engine.is_private(engine.to_number("172.31.255.255")), true)
check("not private 172.32", engine.is_private(engine.to_number("172.32.0.1")), false)

-- Lookup: asset first, then the most specific segment, then internet
local asset, segment = aws.lookup("10.10.90.10")
check("guest asset", asset, "GUEST01")
check("guest segment", segment, "guest")
asset, segment = aws.lookup("10.10.20.150")
check("DHCP address has no asset", asset, nil)
check("DHCP address segment", segment, "finance")
asset, segment = aws.lookup("198.51.100.10")
check("public address", segment, "internet")
asset, segment = aws.lookup("192.168.1.10")
check("unknown private address", segment, nil)

-- Verdicts in AWS (first match wins, default deny)
local action, rule = aws.verdict("10.10.90.10", "10.10.20.10", "tcp", 445)
check("SCN-04 guest to finance", action, "deny")
check("SCN-04 rule", rule, "NM-004")
action, rule = aws.verdict("10.10.90.10", "198.51.100.10", "tcp", 443)
check("guest web", action .. " " .. rule, "allow NM-005")
action, rule = aws.verdict("10.10.20.10", "10.10.80.10", "udp", 88)
check("finance Kerberos to DC01", action .. " " .. rule, "allow NM-010")
action, rule = aws.verdict("10.10.50.10", "10.10.80.30", "tcp", 443)
check("development to finance app", action .. " " .. rule, "deny NM-026")
action, rule = aws.verdict("10.10.20.10", "10.10.70.10", "tcp", 1514)
check("agent to SIEM01", action .. " " .. rule, "allow NM-040")
action, rule = aws.verdict("10.10.20.10", "10.10.70.10", "tcp", 22)
check("SSH to SIEM01", action .. " " .. rule, "deny NM-033")
action, rule = aws.verdict("10.10.20.10", "10.10.70.10", "tcp", 443)
check("other port to SIEM01", action .. " " .. rule, "deny NM-043")
action, rule = aws.verdict("10.10.80.10", "10.10.90.10", "tcp", 50000)
check("unmatched flow (DC01 to guest)", action .. " " .. rule, "deny default")
action, rule = aws.verdict("10.10.70.10", "10.10.20.10", "tcp", 50000)
check("security segment counts as corporate users", action .. " " .. rule, "deny NM-060")
action = aws.verdict("bogus", "10.10.20.10", "tcp", 80)
check("invalid address", action, nil)

-- The same flow can differ between environments (NM-080 exists only in Packet Tracer)
action, rule = pt.verdict("10.10.60.10", "10.10.80.30", "icmp", nil)
check("PT: IT may ping servers", action .. " " .. rule, "allow NM-080")
action = aws.verdict("10.10.60.10", "10.10.80.30", "icmp", nil)
check("AWS: no ICMP rule", action, "deny")

local ok = pcall(engine.new, policy, "lab")
check("unknown environment is an error", ok, false)

print(string.format("%d/%d checks passed (%s)", count - failures, count, _VERSION))
os.exit(failures == 0 and 0 or 1)
