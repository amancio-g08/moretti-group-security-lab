-- Moretti Group lab: network matrix evaluation, in plain Lua (5.2 to 5.4, no Wireshark API).
--
-- Used by the Wireshark plugin (moretti.lua) and tested on its own (tests/test_engine.lua).
-- Semantics follow data/network-matrix.yaml: rules are evaluated in order, the first rule whose
-- source, destination and service all match decides, and anything unmatched gets the default
-- action (deny). "internet" matches any address outside the private ranges.

local engine = {}

local function to_number(address)
  local a, b, c, d = string.match(address or "", "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return nil end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
  return ((a * 256 + b) * 256 + c) * 256 + d
end
engine.to_number = to_number

-- True when address (a number) is inside net/bits. Division instead of bit operators keeps the
-- code valid on Lua 5.2, which Wireshark 4.2 embeds.
local function contains(net_number, bits, address)
  local size = 2 ^ (32 - bits)
  return math.floor(net_number / size) == math.floor(address / size)
end

local PRIVATE = {
  { to_number("10.0.0.0"), 8 },
  { to_number("172.16.0.0"), 12 },
  { to_number("192.168.0.0"), 16 },
}

local function is_private(address)
  for _, range in ipairs(PRIVATE) do
    if contains(range[1], range[2], address) then return true end
  end
  return false
end
engine.is_private = is_private

local function prepare(endpoints)
  local out = {}
  for _, e in ipairs(endpoints) do
    if e.internet then
      out[#out + 1] = { internet = true }
    else
      out[#out + 1] = { number = to_number(e.net), bits = e.bits }
    end
  end
  return out
end

local function endpoint_matches(endpoints, address)
  for _, e in ipairs(endpoints) do
    if e.internet then
      if not is_private(address) then return true end
    elseif contains(e.number, e.bits, address) then
      return true
    end
  end
  return false
end

-- proto: "tcp", "udp", "icmp" or anything else; port: destination port (nil for icmp/other).
local function service_matches(ports, proto, port)
  for _, p in ipairs(ports) do
    if p.proto == "any" then return true end
    if p.proto == proto then
      if proto == "icmp" then return true end
      if port and port >= p.lo and port <= p.hi then return true end
    end
  end
  return false
end

--- Builds an evaluator for one environment ("pt" or "aws") of a policy table.
function engine.new(policy, environment)
  local rules = policy.rules[environment]
  if not rules then error("unknown environment '" .. tostring(environment) .. "'") end

  local self = { environment = environment, default_action = policy.default_action }
  local prepared = {}
  for _, rule in ipairs(rules) do
    prepared[#prepared + 1] = {
      id = rule.id, action = rule.action, ports = rule.ports,
      src = prepare(rule.src), dst = prepare(rule.dst),
    }
  end
  local segments = {}
  for _, s in ipairs(policy.segments) do
    segments[#segments + 1] = { id = s.id, number = to_number(s.net), bits = s.bits }
  end
  -- Most specific network first, like a routing table.
  table.sort(segments, function(x, y) return x.bits > y.bits end)
  local assets = {}
  for _, a in ipairs(policy.assets) do assets[a.ip] = a end

  --- Asset ID (or nil) and segment ("internet" outside private space, nil if unknown).
  function self.lookup(address)
    local number = to_number(address)
    if not number then return nil, nil end
    local asset = assets[address]
    if asset then return asset.id, asset.segment end
    for _, s in ipairs(segments) do
      if contains(s.number, s.bits, number) then return nil, s.id end
    end
    if not is_private(number) then return nil, "internet" end
    return nil, nil
  end

  --- Action ("allow"/"deny") and the deciding rule ID ("default" when no rule matched).
  function self.verdict(src, dst, proto, dst_port)
    local s, d = to_number(src), to_number(dst)
    if not s or not d then return nil, nil end
    for _, rule in ipairs(prepared) do
      if endpoint_matches(rule.src, s) and endpoint_matches(rule.dst, d)
          and service_matches(rule.ports, proto, dst_port) then
        return rule.action, rule.id
      end
    end
    return self.default_action, "default"
  end

  return self
end

return engine
