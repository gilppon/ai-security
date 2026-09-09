from execution.sandbox.limits import IsolationLimits, UnavailableIsolationBackend


def test_unavailable_os_isolation_never_silently_satisfies_required_policy() -> None:
    backend = UnavailableIsolationBackend()
    try:
        backend.apply(object(), IsolationLimits(require_os_enforcement=True))
    except RuntimeError as exc:
        assert "unavailable" in str(exc).lower()
    else:  # pragma: no cover - assertion makes the fail-open regression explicit
        raise AssertionError("required OS isolation was silently bypassed")

