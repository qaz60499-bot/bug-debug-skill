# 18 — Function-level Emulation

## Purpose

Use this route only for a bounded local check of one small function. The goal is to verify a specific hypothesis about local inputs and outputs, not to claim full application behavior.

## Activation criteria

Use only when:

- the function boundary is known;
- the expected inputs and outputs are documented;
- outside dependencies are listed;
- the question is local to that function;
- the result answers one hypothesis.

## Required record

```text
Function/address/token:
Artifact fingerprint:
Reason for bounded local check:
Inputs documented:
State assumptions:
Outside dependencies:
Tool/version:
Observed result:
What this proves:
What this does not prove:
Next minimal test:
```

## Evidence status

The result is evidence only for the documented local check. Any broader behavior claim remains an Inference until supported by independent observations.

## Stop rule

Do not generalize from one local function check to the entire program.
