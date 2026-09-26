# Project 02 — Network Traffic Analysis

Structured investigations of captures produced by lab scenarios, answering who, what, when,
where and how, with a timeline, Wireshark filters and the reasoning behind each conclusion.

**Status:** planned for Phase 7.

Planned layout:

```
project-02-pcap/
├── pcaps/
│   └── curated/     # reviewed captures that back a published report (committed)
├── analysis/        # filters, notes and reasoning per investigation
├── evidence/        # extracted evidence with hashes
└── reports/         # investigation reports
```

Raw captures are git-ignored by default; only curated captures are committed. Evidence is never
invented — anything the capture cannot show is stated explicitly.
