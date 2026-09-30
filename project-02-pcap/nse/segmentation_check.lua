-- Moretti Group lab: comparison logic for the segmentation audit, in plain Lua (no Nmap API).
--
-- Kept separate from the NSE script so it can be unit-tested without Nmap
-- (project-02-pcap/tests/test_segmentation.lua). Given the expected reachability table and the
-- observed state of each target, it produces the list of mismatches.

local M = {}

-- observed[i] is the state of checks[i]: "open", "closed" or "filtered" (Nmap's words).
-- A port that answers is "open"; one that is refused or times out is treated as blocked.
-- Expected "allow" should be reachable (open); expected "deny" should be blocked.
function M.compare(checks, observed)
  local reachable = { open = true, closed = false, filtered = false }
  local mismatches, tested = {}, 0
  for i, check in ipairs(checks) do
    local state = observed[i]
    if state ~= nil then
      tested = tested + 1
      local is_reachable = reachable[state]
      local should = check.expected == "allow"
      if is_reachable ~= should then
        mismatches[#mismatches + 1] = {
          from_id = check.from_id, to_id = check.to_id, to_ip = check.to_ip,
          port = check.port, expected = check.expected, rule = check.rule, observed = state,
          kind = should and "unexpected-block" or "segmentation-gap",
        }
      end
    end
  end
  return { tested = tested, mismatches = mismatches }
end

-- Only the checks that start from this host's address are ours to run.
function M.checks_from(targets, my_ip)
  local mine = {}
  for _, check in ipairs(targets.checks) do
    if check.from_ip == my_ip then mine[#mine + 1] = check end
  end
  return mine
end

return M
