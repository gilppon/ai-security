# Phase 8 Implementation Plan

## Scope

Build a proprietary, deterministic red-team regression harness for the five
architecture metrics: prompt injection, RAG poisoning, MCP escalation, secret
leakage, and tool abuse.

## Architecture

1. Strict, server-owned `ProbeTemplate` and `ProbeSuite` models.
2. Replaceable target evaluators registered in a bounded `ScenarioRunner`.
3. Exact expected-versus-actual decision matching; evaluator absence, exception,
   or invalid return is always a failed probe and a fail-closed harness decision.
4. Deterministic regression and per-category block/pass rates in basis points.
5. A `SecurityEvent` and structured audit record for every probe and suite run.
6. Reports expose payload fingerprints and metadata only, never raw probes.

## Boundaries

- No shell, filesystem, network, MCP, or tool execution capability is added.
- The runner invokes only explicitly registered in-process evaluator objects.
- No LLM, statistical model, or third-party security rule source participates in
  evaluation or final decisions.
- Probe count and serialized payload size are bounded to resist resource abuse.
- No public API is added in this phase; this is an offline/CI regression harness.

## Verification

- Unit tests: model bounds, deterministic scoring, exact decision matching.
- Security tests: missing/failing evaluator, raw-probe audit exclusion, full
  category coverage, and failed-regression default deny.
- Integration tests: real Prompt, RAG, MCP, Output, and Tool controls execute
  through adapters and produce a complete passing regression report.
- Run the full pytest suite, package build, Compose configuration validation,
  and focused secret/direct-execution scans.
