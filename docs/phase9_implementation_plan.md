# Phase 9A — OS Isolation Backend

Status: **COMPLETE ON THE VERIFIED WINDOWS 11 HOST**. All Phase 9 controls are
enforced before untrusted code starts and covered by host integration tests.

## Scope

Close the first part of the V1 deployment boundary without weakening the
deterministic Process Firewall.  The executor receives a replaceable isolation
backend after authorization and before any process output is released.

## Implemented

- Immutable `IsolationLimits` with bounded CPU time and memory settings.
- `ProcessIsolationBackend` contract and fail-closed `IsolationError`.
- Windows Job Object backend for CPU-time and per-process memory limits.
- Windows children are created suspended, assigned to the configured Job
  Object, and resumed only after the binding succeeds.
- SafeExecutor integration with explicit isolation failure reason codes.
- Windows integration tests cover direct backend launch and the complete
  Process Firewall capability-to-execution path.
- Capability-free AppContainer execution provides the network and restricted
  token boundary when network isolation is required.
- The sandbox grants executable and workspace paths read-only and strips
  unneeded token privileges.
- AppContainer children start suspended, bind to the resource-limit Job Object,
  and resume only after both boundaries are active.

## Remaining Phase 9 work

- None for the verified Windows 11 host. Other operating systems remain
  fail-closed until an equivalent host adapter and enforcement suite exists.

## Phase 9B progress

- Added a side-effect-free host capability probe.
- Added explicit `require_network_isolation` handling in `SafeExecutor`.
- Network enforcement uses an AppContainer with no network capabilities; no
  global Windows Firewall rules are changed.
- Network-only isolation requests now enter the pre-launch backend path; they
  cannot silently execute without a network boundary.

## Phase 9C progress

- Added a deterministic hardened-readiness decision gate.
- Production integration must deny startup unless CPU/memory, network, and
  restricted-token capabilities are all reported by the host adapter.

## Current verification

- Focused sandbox/process/readiness tests: `20 passed` on Windows 11.
- Full suite: `279 passed, 2 skipped`.
- Source distribution and wheel build successfully with the declared
  `flatbuffers` runtime dependency.
- Dependency audit: no known vulnerabilities found.
- Actual Windows Job Object launch now passes from Process Firewall capability
  consumption through suspended launch, binding, resume, and bounded result.
- AppContainer integration proves restricted child and descendant tokens,
  denied loopback network access, denied workspace writes, read access, and
  exclusion of an unapproved environment secret.
- Resource tests prove CPU-time and memory ceilings terminate abusive children.
