from resource_security.models import ResourceAuthorizationResult
from resource_security.network.firewall import NetworkFirewall


def authorize_redirect(
    firewall: NetworkFirewall,
    target_url: str,
    *,
    session_id: str | None = None,
) -> ResourceAuthorizationResult:
    return firewall.authorize_redirect(target_url, session_id=session_id)
