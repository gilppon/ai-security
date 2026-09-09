"""Host capability probing without mutating host security state."""

from __future__ import annotations

import os
import ctypes

from pydantic import BaseModel, ConfigDict


class HostIsolationCapabilities(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    cpu_memory_limits: bool
    network_isolation: bool
    restricted_token: bool

    @property
    def hardened_ready(self) -> bool:
        return self.cpu_memory_limits and self.network_isolation and self.restricted_token


def probe_host_isolation_capabilities() -> HostIsolationCapabilities:
    """Return conservative capabilities; do not infer missing controls."""
    if os.name != "nt":
        return HostIsolationCapabilities(cpu_memory_limits=False, network_isolation=False, restricted_token=False)
    try:
        process_model = ctypes.WinDLL("processmodel.dll", use_last_error=True)
        appcontainer_available = bool(
            getattr(process_model, "Experimental_CreateProcessInSandbox", None)
        )
    except (AttributeError, OSError):
        appcontainer_available = False
    return HostIsolationCapabilities(
        cpu_memory_limits=True,
        network_isolation=appcontainer_available,
        restricted_token=appcontainer_available,
    )
