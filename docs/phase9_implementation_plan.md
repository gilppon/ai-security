# Phase 9A — OS Isolation Backend

## Scope

Close the first part of the V1 deployment boundary without weakening the
deterministic Process Firewall.  The executor receives a replaceable isolation
backend after authorization and before any process output is released.

## Implemented

- Immutable `IsolationLimits` with bounded CPU time and memory settings.
- `ProcessIsolationBackend` contract and fail-closed `IsolationError`.
- Windows Job Object backend for CPU-time and per-process memory limits.
- SafeExecutor integration with explicit isolation failure reason codes.
- Network denial is rejected by the Job Object backend because Job Objects do
  not provide a network boundary; no false claim of network isolation is made.

## Remaining Phase 9 work

- Firewall-backed network isolation backend.
- Read-only workspace and restricted-token/AppContainer hardening.
- Integration tests on a Windows runner with enforced CPU/memory limits.

## Phase 9B progress

- Added a side-effect-free host capability probe.
- Added explicit `require_network_isolation` handling in `SafeExecutor`.
- Network enforcement remains fail-closed because Job Objects do not provide a
  network boundary and no firewall rules are changed implicitly.

## Phase 9C progress

- Added a deterministic hardened-readiness decision gate.
- Production integration must deny startup unless CPU/memory, network, and
  restricted-token capabilities are all reported by the host adapter.
