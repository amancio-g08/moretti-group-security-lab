# Project 02 — Network Traffic Analysis

[Português](README.md) | **English**

Structured investigations of captures produced by lab scenarios, answering who, what, when,
where and how, with a timeline, Wireshark filters and the reasoning behind each conclusion.

**Status:** the **Wireshark plugin in Lua** is ready and tested. The investigations come in
phase 7, when the scenarios run in the lab and real captures exist.

## Wireshark plugin (Lua)

Lua is one of the languages I use most, and it is Wireshark's plugin language. So instead of only
analyzing captures, I taught Wireshark about the company: every packet gets a **Moretti Group**
section saying which host and segment it came from, where it went, and whether that flow is
**allowed or forbidden by the network matrix**, with the deciding rule.

```
Moretti Group: GUEST01 (guest) -> WS-FIN01 (finance): deny (NM-004)
```

Filter `moretti.verdict == "deny"` to see every flow that breaks the policy at once, or
`moretti.src.segment == "guest"` to follow the visitor.

- The asset and rule table is **generated from `data/`**, like the rest of the project.
- It understands connections like a real firewall: only the start of a flow is judged, and the
  reply inherits the verdict.
- It works with the AWS or the Packet Tracer rules (a Wireshark preference).

**How it was proven correct:**
- unit tests of the engine in plain Lua;
- a **differential test** that compares the Lua engine with an independent Python evaluator on
  **203,228 flows**, with no disagreement;
- an end-to-end test with `tshark` on a synthetic capture.

All of it runs in CI.

Installation, use and limitations: [documentation/wireshark-plugin.md](documentation/wireshark-plugin.md).

## Layout

```
project-02-pcap/
├── wireshark/       # Lua plugin: moretti.lua, policy_engine.lua, moretti_policy.lua (generated)
├── tools/           # policy table generator
├── tests/           # engine tests and the synthetic capture builder
├── nse/             # Lua segmentation audit (Nmap), targets generated from data/
├── documentation/   # plugin documentation
├── reports/         # investigation report template
└── (phase 7)        # pcaps/curated with the reviewed captures
```

Raw captures are git-ignored by default; only curated captures are committed. Evidence is never
invented — anything the capture cannot show is stated explicitly.
