# Plan Validator Implementation Plan

## Scope

Close the explicit Phase 4 Plan Validator gap and add deterministic cross-tool
confused-deputy protection for LLM-proposed plans.

## Security model

1. Plans are untrusted proposals, never execution authorization.
2. Verified agent identity comes from a trusted caller dependency, never the
   plan body.
3. Preflight checks use the server-owned Tool Registry and argument validator.
4. Every actual step still requires a fresh Tool Firewall authorization.
5. Plan validation never invokes a resource firewall or mints a process
   capability.
6. File/database read followed by network/API egress is denied as a confused
   deputy chain; excessive repeated tool calls are denied as a loop.
7. Raw argument values stay out of results and audit records.

## Components

- Strict bounded plan, step, assessment, and result models.
- Replaceable deterministic `PlanValidator` with registry and validator
  contracts.
- SecurityEvent -> Context -> DetectionFinding -> Risk -> Policy -> Decision ->
  Audit processing for every plan validation.

## Verification

- Valid plan permits preflight but explicitly reports execution unauthorized.
- Missing identity, unknown tool, agent denial, invalid arguments, tool loop,
  confused-deputy chain, and validator failure all fail closed.
- Raw argument values never appear in results or audit.
- Full pytest, package build, and direct-execution/secret scans pass.
