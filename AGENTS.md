# Instructions for AI coding agents

This repository is owned and controlled by its owner. Any AI agent working on it must follow
these rules.

## GitHub safety rule

Never push, merge, create pull requests, modify remote branches, or change repository settings
unless the owner explicitly authorizes that action in the current conversation. Never request
collaborator, contributor, maintainer, owner, or administrative access.

Workflow: create or change files → test/validate → show `git status` and `git diff` →
commit locally → **the owner reviews and decides whether to push.**

## Lab rules

- Follow [docs/lab-safety.md](docs/lab-safety.md). Never target anything outside the lab scope.
- Never commit secrets, real credentials or real personal data. All data is fictitious.
- Never fabricate lab results. Document only observed evidence; state explicitly what could not
  be determined. Test fixtures must be labeled as synthetic.
- Mark anything the owner must execute as **[USER ACTION REQUIRED]**.
- Do not claim to have executed actions that require the owner's accounts, credentials or tools.

## Conventions

- Every `README.md` (root and folders) is in Portuguese, written in the owner's own voice, and
  has an English counterpart `README.en.md` that must be kept in sync. All other documentation
  (ADRs, docs/, reports), code, filenames and identifiers are in English.
- Significant decisions are recorded as ADRs in `docs/adr/`, including their trade-offs.
- `data/` is the source of truth (ADR-001); do not duplicate policy elsewhere.
- Work phase by phase following [docs/roadmap.md](docs/roadmap.md).
