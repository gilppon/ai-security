from execution.sandbox.capabilities import probe_host_isolation_capabilities


def test_capability_probe_is_conservative() -> None:
    capabilities = probe_host_isolation_capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.restricted_token is False
    assert capabilities.hardened_ready is False

