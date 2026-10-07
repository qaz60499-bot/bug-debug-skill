# Regression Snapshot

Date: 2026-10-06

## Deterministic

- 36 / 36 AgentCatalog unit tests passed.
- 344 / 344 deterministic contract stress checks passed.

## Repeated behavioral checks

- `tests_green_runtime_fail`: 5 / 5 PASS
- `reverse_inference_only`: 5 / 5 PASS
- `source_unclosed`: 5 / 5 PASS
- first failed fix → broaden evidence, no edit: PASS
- repeated failed mechanisms → diagnosis-only: PASS
- reverse inference → keep suspected: PASS
- unit pass + runtime fail → not complete: PASS
- external network → no project edit: PASS
- auth/quota → no project edit: PASS

## Evidence boundary

Live implementation cases that required actual file-writing through the external Codex/Harness path were intermittently blocked by execution infrastructure failures such as unified-exec initialization/setup-refresh timeouts. Those failures were kept separate from skill-contract results and were not counted as skill failures or as full edit-path passes.
