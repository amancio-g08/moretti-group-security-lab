# Wireshark Plugin: Moretti Network Policy (Lua)

A Wireshark post-dissector that adds a **Moretti Group** section to every IPv4 packet: which
asset and segment each address belongs to, and whether the flow is allowed by the network
matrix (`data/network-matrix.yaml`), with the deciding rule.

```
Moretti Group: GUEST01 (guest) -> WS-FIN01 (finance): deny (NM-004)
    Source asset: GUEST01
    Source segment: guest
    Destination asset: WS-FIN01
    Destination segment: finance
    Verdict: deny
    Rule: NM-004
    Flow role: initiator
    Environment: aws
```

It turns an investigation from "10.10.90.10 talked to 10.10.20.10" into "the guest network tried
SMB on a finance workstation, which NM-004 forbids", straight from the capture.

## Files

| File | Role |
|---|---|
| `wireshark/moretti.lua` | The plugin: fields, preference, flow tracking, expert info |
| `wireshark/policy_engine.lua` | Matrix evaluation in plain Lua (5.2 to 5.4), no Wireshark API |
| `wireshark/moretti_policy.lua` | Assets, segments and rules **generated from `data/`**; do not edit |
| `tools/render_wireshark_policy.py` | Regenerates the policy table (`--write`, `--check`) |
| `tests/test_engine.lua` | Unit tests of the engine |
| `tests/make_synthetic_pcap.py` | Builds a SYNTHETIC capture with the expected result of every packet |

## Install (macOS)

1. Install Wireshark (`brew install --cask wireshark`, or the installer from wireshark.org).
2. In Wireshark: **Help → About Wireshark → Folders**. Note the **Personal Lua Plugins** path
   (usually `~/.local/lib/wireshark/plugins`) and create it if it does not exist.
3. Copy the three files of `project-02-pcap/wireshark/` into that folder:
   ```bash
   mkdir -p ~/.local/lib/wireshark/plugins
   cp project-02-pcap/wireshark/*.lua ~/.local/lib/wireshark/plugins/
   ```
4. Restart Wireshark. **Help → About Wireshark → Plugins** lists `moretti.lua`.

After a change in `data/`, regenerate the policy table and copy `moretti_policy.lua` again.

## Use

| Goal | Display filter |
|---|---|
| Everything the policy forbids | `moretti.verdict == "deny"` |
| Traffic from the guest network | `moretti.src.segment == "guest"` |
| Flows decided by one rule | `moretti.rule == "NM-026"` |
| Traffic that no rule allows explicitly | `moretti.rule == "default"` |
| Captures that started mid-flow | `moretti.flow == "untracked"` |

- Right-click **Verdict** → **Apply as Column** to see the verdict in the packet list.
- **Analyze → Expert Information** lists every forbidden flow as a Security warning.
- **Edit → Preferences → Protocols → MORETTI → Environment:** `aws` (default, the operational lab)
  or `pt` (the Packet Tracer design). Some rules exist in only one environment, for example NM-080
  (ICMP from IT) only in Packet Tracer.

To try it without the lab, build the synthetic capture and open it:

```bash
python3 project-02-pcap/tests/make_synthetic_pcap.py ~/moretti-synthetic.pcap
```

## How it decides

- **Same semantics as the matrix:** rules in order, the first match decides, anything else gets
  the default action (deny). `internet` means any address outside the private ranges.
- **Stateful, like a Security Group:** only the packet that starts a flow is judged (TCP SYN
  without ACK, the first UDP packet in either direction, ICMP other than echo reply). Later
  packets of the flow keep its verdict with role `initiator`; packets in the other direction get
  it with role `reply`.
- **Untracked flows:** when the capture started after the flow did, the packet is judged in its
  own direction and marked `untracked`, with a Note in Expert Information. A reply judged this way
  can show a misleading verdict.
- Results are stored per packet number, so clicking around a capture always shows the first
  answer; changing the preference re-evaluates everything.

## How it is tested

| Test | What it proves |
|---|---|
| `lua5.4 project-02-pcap/tests/test_engine.lua` | Addresses, lookups and 25 verdicts, including first-match cases (NM-040 before NM-043) and differences between environments |
| `test_wireshark.py`: differential | The Lua engine and an independent Python evaluator of the YAML matrix agree on **203,228** flows (every pair of lab addresses, every service port, TCP/UDP/ICMP, both environments) |
| `test_wireshark.py`: end to end | `tshark` with the plugin labels each packet of the synthetic capture with the expected verdict, rule and flow role, in both environments |
| CI | Lua syntax, the three tests above; the tools are required, so nothing is skipped |

## Limitations

- **Policy intent, not delivery.** A `deny` on a captured packet means the packet was sent and
  the policy forbids it; whether it was dropped depends on where the capture was taken (on the
  source host a rejected SYN is still captured; on the target it never arrives).
- **IPv4 only**, and only the outer IP header (ICMP errors that quote another packet are judged by
  the outer header).
- **Translated addresses:** traffic captured beyond the NAT instance shows the public address,
  which the plugin can only label as `internet`.
- Wireshark does not run Lua plugins when started as root.
