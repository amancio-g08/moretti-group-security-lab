-- Unit tests of the segmentation audit comparison logic, against the generated targets table.
--   lua5.4 project-02-pcap/tests/test_segmentation.lua

local check = dofile("project-02-pcap/nse/segmentation_check.lua")
local targets = dofile("project-02-pcap/nse/moretti_targets.lua")

local failures, count = 0, 0
local function ok(name, cond)
  count = count + 1
  if not cond then failures = failures + 1; print("FAIL " .. name) end
end

-- checks_from selects only the flows that start at the given address
local guest = check.checks_from(targets, "10.10.90.10")
ok("guest has checks", #guest > 0)
for _, c in ipairs(guest) do ok("from guest only", c.from_ip == "10.10.90.10") end

-- Build the "matrix holds" observation: allow -> open, deny -> closed. Expect no mismatch.
local observed = {}
for i, c in ipairs(guest) do observed[i] = (c.expected == "allow") and "open" or "closed" end
local clean = check.compare(guest, observed)
ok("all tested", clean.tested == #guest)
ok("no mismatch when reality matches the matrix", #clean.mismatches == 0)

-- Flip one denied flow to open: a segmentation gap must be reported.
local gap_index
for i, c in ipairs(guest) do if c.expected == "deny" then gap_index = i; break end end
ok("guest has a denied flow", gap_index ~= nil)
observed[gap_index] = "open"
local gap = check.compare(guest, observed)
ok("one mismatch", #gap.mismatches == 1)
ok("labeled segmentation-gap", gap.mismatches[1].kind == "segmentation-gap")
observed[gap_index] = "closed"

-- Flip one allowed flow to filtered: an unexpected block must be reported.
local allow_index
for i, c in ipairs(guest) do if c.expected == "allow" then allow_index = i; break end end
if allow_index then
  observed[allow_index] = "filtered"
  local blocked = check.compare(guest, observed)
  ok("unexpected block reported", #blocked.mismatches == 1)
  ok("labeled unexpected-block", blocked.mismatches[1].kind == "unexpected-block")
end

-- A nil observation (not probed) is skipped, not counted as a mismatch.
local partial = {}
partial[1] = observed[1]
local skipped = check.compare(guest, partial)
ok("untested flows are skipped", skipped.tested == 1)

print(string.format("%d/%d checks passed (%s)", count - failures, count, _VERSION))
os.exit(failures == 0 and 0 or 1)
