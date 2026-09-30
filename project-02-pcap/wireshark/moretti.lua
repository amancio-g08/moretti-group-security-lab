-- Moretti Group lab: Wireshark post-dissector that labels each IPv4 packet with the asset and
-- segment at each end and with the network matrix verdict for its flow.
--
-- Install: copy moretti.lua, policy_engine.lua and moretti_policy.lua into the same Wireshark
-- plugin folder (Help > About Wireshark > Folders > Personal Lua Plugins), then restart
-- Wireshark. Details: project-02-pcap/documentation/wireshark-plugin.md.
--
-- Filters:  moretti.verdict == "deny"   moretti.src.segment == "guest"   moretti.rule == "NM-004"
--
-- Like a stateful firewall, only the packet that starts a flow is judged (TCP SYN, first UDP
-- packet, ICMP echo request); packets of the same flow and its replies inherit that verdict.

local plugin_dir = debug.getinfo(1, "S").source:match("^@(.*[/\\])") or ""
local engine = dofile(plugin_dir .. "policy_engine.lua")
local policy = dofile(plugin_dir .. "moretti_policy.lua")

local moretti = Proto("moretti", "Moretti Group network policy")

local fields = {
  src_asset = ProtoField.string("moretti.src.asset", "Source asset"),
  src_segment = ProtoField.string("moretti.src.segment", "Source segment"),
  dst_asset = ProtoField.string("moretti.dst.asset", "Destination asset"),
  dst_segment = ProtoField.string("moretti.dst.segment", "Destination segment"),
  verdict = ProtoField.string("moretti.verdict", "Verdict"),
  rule = ProtoField.string("moretti.rule", "Rule"),
  flow = ProtoField.string("moretti.flow", "Flow role",
    base.NONE, nil, nil, "initiator, reply, or untracked (the capture missed the start of the flow)"),
  environment = ProtoField.string("moretti.environment", "Environment"),
}
moretti.fields = {
  fields.src_asset, fields.src_segment, fields.dst_asset, fields.dst_segment,
  fields.verdict, fields.rule, fields.flow, fields.environment,
}

local expert_deny = ProtoExpert.new("moretti.deny", "Flow not allowed by the Moretti network matrix",
  expert.group.SECURITY, expert.severity.WARN)
local expert_untracked = ProtoExpert.new("moretti.untracked",
  "Start of the flow not captured: verdict judged from this packet's direction",
  expert.group.SEQUENCE, expert.severity.NOTE)
moretti.experts = { expert_deny, expert_untracked }

moretti.prefs.environment = Pref.string("Environment", "aws",
  "Rules of which environment to apply: aws (operational lab) or pt (Packet Tracer design)")

local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")
local f_tcp_dport = Field.new("tcp.dstport")
local f_tcp_sport = Field.new("tcp.srcport")
local f_tcp_syn = Field.new("tcp.flags.syn")
local f_tcp_ack = Field.new("tcp.flags.ack")
local f_udp_dport = Field.new("udp.dstport")
local f_udp_sport = Field.new("udp.srcport")
local f_icmp_type = Field.new("icmp.type")

local engines = {}
local flows = {}    -- flow key -> { verdict, rule } of the packet that started it
local results = {}  -- packet number -> result, so re-dissection shows the same answer

local function reset()
  flows, results = {}, {}
end
moretti.init = reset
moretti.prefs_changed = reset

local function evaluator()
  local environment = moretti.prefs.environment
  if not policy.rules[environment] then environment = "aws" end
  engines[environment] = engines[environment] or engine.new(policy, environment)
  return engines[environment], environment
end

local function value(extractor)
  local info = extractor()
  return info and info.value
end

local function is_set(flag)
  return flag == true or flag == 1
end

local function classify(eval, src, dst)
  local proto, sport, dport, starts
  if f_tcp_dport() then
    proto, sport, dport = "tcp", value(f_tcp_sport), value(f_tcp_dport)
    starts = is_set(value(f_tcp_syn)) and not is_set(value(f_tcp_ack))
  elseif f_udp_dport() then
    proto, sport, dport = "udp", value(f_udp_sport), value(f_udp_dport)
    starts = true  -- the first packet seen in either direction starts a UDP flow
  elseif f_icmp_type() then
    proto = "icmp"
    starts = value(f_icmp_type) ~= 0  -- echo replies (type 0) never start a flow
  else
    proto, starts = "ip", true
  end

  local forward = table.concat({ proto, src, tostring(sport), dst, tostring(dport) }, "|")
  local reverse = table.concat({ proto, dst, tostring(dport), src, tostring(sport) }, "|")
  if flows[forward] then
    return flows[forward].verdict, flows[forward].rule, "initiator"
  elseif flows[reverse] then
    return flows[reverse].verdict, flows[reverse].rule, "reply"
  end
  local verdict, rule = eval.verdict(src, dst, proto, dport)
  if starts then
    flows[forward] = { verdict = verdict, rule = rule }
    return verdict, rule, "initiator"
  end
  return verdict, rule, "untracked"
end

local function label(asset, segment)
  return string.format("%s (%s)", asset or "?", segment or "unknown")
end

function moretti.dissector(_, pinfo, tree)
  local src_info, dst_info = f_ip_src(), f_ip_dst()
  if not src_info or not dst_info then return end
  local src, dst = tostring(src_info.value), tostring(dst_info.value)
  local eval, environment = evaluator()

  local result = results[pinfo.number]
  if not result then
    local verdict, rule, role = classify(eval, src, dst)
    result = { verdict = verdict, rule = rule, role = role }
    results[pinfo.number] = result
  end

  local src_asset, src_segment = eval.lookup(src)
  local dst_asset, dst_segment = eval.lookup(dst)
  local subtree = tree:add(moretti)
  subtree:set_text(string.format("Moretti Group: %s -> %s: %s (%s)",
    label(src_asset, src_segment), label(dst_asset, dst_segment), result.verdict, result.rule))
  if src_asset then subtree:add(fields.src_asset, src_asset) end
  if src_segment then subtree:add(fields.src_segment, src_segment) end
  if dst_asset then subtree:add(fields.dst_asset, dst_asset) end
  if dst_segment then subtree:add(fields.dst_segment, dst_segment) end
  subtree:add(fields.verdict, result.verdict)
  subtree:add(fields.rule, result.rule)
  subtree:add(fields.flow, result.role)
  subtree:add(fields.environment, environment)
  if result.verdict == "deny" then
    subtree:add_proto_expert_info(expert_deny, "Not allowed by " .. result.rule .. " (" .. environment .. ")")
  end
  if result.role == "untracked" then
    subtree:add_proto_expert_info(expert_untracked)
  end
end

register_postdissector(moretti)
