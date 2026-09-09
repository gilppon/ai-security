from evaluation.faults import DeterministicFaultInjector, FaultStage


def test_fault_injector_is_bounded_and_deterministic() -> None:
    injector = DeterministicFaultInjector(frozenset({FaultStage.DETECT}))

    try:
        injector.check(FaultStage.DETECT.value)
    except RuntimeError as exc:
        assert str(exc) == "deterministic fault injected"
    else:  # pragma: no cover
        raise AssertionError("fault was not injected")

    assert injector.hits(FaultStage.DETECT) == 1
    injector.check(FaultStage.CONTEXT.value)
    assert injector.hits(FaultStage.CONTEXT) == 0

