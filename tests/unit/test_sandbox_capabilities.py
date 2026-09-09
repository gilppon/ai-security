import os

from execution.sandbox.capabilities import probe_host_isolation_capabilities


def test_capability_probe_reports_only_available_host_controls() -> None:
    capabilities = probe_host_isolation_capabilities()

    if os.name == "nt" and capabilities.network_isolation:
        assert capabilities.restricted_token is True
        assert capabilities.hardened_ready is True
    else:
        assert capabilities.network_isolation is False
        assert capabilities.restricted_token is False
        assert capabilities.hardened_ready is False
