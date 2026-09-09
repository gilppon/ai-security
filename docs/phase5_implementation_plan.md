# Phase 5 Implementation Plan

## Scope

Complete the remaining resource-control plane without adding a public execution
surface:

1. Process Firewall
2. Safe Executor
3. Database Firewall authorization
4. API Firewall authorization
5. Tool Firewall integration for every new capability

The required authorization path is:

`Tool Firewall -> Resource Firewall -> deterministic Decision -> Audit`

Process execution adds one more mandatory boundary:

`Tool Firewall -> Process Firewall -> one-time capability -> Safe Executor`

## Security invariants

- Default deny on missing identity, registration, grant, dependency, or state.
- Commands are structured argument vectors; shell command strings are invalid.
- Safe Executor always uses `shell=False` and never searches an untrusted `PATH`.
- Executables, working directories, script paths, URLs, and network destinations
  are resolved before authorization.
- Process capabilities are opaque, short-lived, and single-use.
- Safe Executor accepts only a Process Firewall capability, never raw arguments.
- Database access uses a structured query intent; raw SQL is not accepted.
- API access is restricted to registered methods, origins, paths, fields, and
  query parameters, then re-authorized by the Network Firewall.
- No database query, HTTP request, or process execution is exposed as a public
  FastAPI route in this phase.
- Audit records contain fingerprints and metadata, never raw command output,
  request bodies, SQL, credentials, capability tokens, or secrets.

## Implementation

### Process Firewall and Safe Executor

- Add immutable process grants with exact resolved executable paths, allowed
  argument prefixes, working roots, timeouts, and output limits.
- Reject shell executables, shell-control flags, unsupported argument shapes,
  unapproved working directories, and unapproved path arguments.
- Mint a one-time in-memory capability only after an allow decision.
- Execute only the stored authorized specification with `shell=False`, a minimal
  environment, bounded runtime, and bounded stdout/stderr collection.
- Return exit metadata, byte counts, and output fingerprints instead of raw
  output. Terminate on timeout or output overflow.

### Database Firewall

- Authorize structured operation/table/column/predicate metadata against
  server-owned grants.
- Do not accept or execute raw SQL.
- Produce deterministic reason codes and an audit record for every request.

### API Firewall

- Match a server-owned endpoint registration by API id, method, origin, and
  normalized exact path.
- Reject undeclared query parameters and body fields.
- Delegate final destination resolution and private-network checks to the
  Network Firewall before approval.
- Produce deterministic reason codes and an audit record for every request.

### Tool Firewall integration

- Extend tool capabilities with PROCESS, DATABASE, and API.
- Require capability-specific typed resource request objects.
- Return the opaque process capability only to the internal caller after the
  Tool Firewall and Process Firewall both allow the action.
- Preserve the existing public API default-deny behavior because callers cannot
  self-assert verified identities.

## Verification

- Unit tests for every allow and deny reason, including dependency failure.
- Tests proving shell strings and shell-control flags are rejected.
- Tests proving capability expiry and replay are denied.
- Tests proving `shell=False`, exact executable use, timeout handling, bounded
  output, and absence of raw output in results/audit.
- Tests proving raw SQL is rejected and database grants are least privilege.
- Tests proving API registration is exact and Network Firewall denial propagates.
- Tool Firewall integration tests for all three new capabilities.
- Full `pytest` run and targeted search for subprocess/network/filesystem bypasses.

## Boundaries

- This phase is a constrained subprocess harness, not a claim of container,
  kernel, CPU, or memory isolation. Strong OS isolation remains a deployment
  boundary for a later phase.
- No third-party security project source code is used.
