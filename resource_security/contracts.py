from typing import Protocol

from resource_security.filesystem.models import FilesystemAuthorizationRequest
from resource_security.models import ResourceAuthorizationResult
from resource_security.network.models import NetworkAuthorizationRequest
from resource_security.process.models import ProcessAuthorizationRequest, ProcessAuthorizationResult
from resource_security.database.models import DatabaseAuthorizationRequest
from resource_security.api.models import APIAuthorizationRequest


class FilesystemAuthorizer(Protocol):
    def authorize(self, request: FilesystemAuthorizationRequest) -> ResourceAuthorizationResult: ...


class NetworkAuthorizer(Protocol):
    def authorize(self, request: NetworkAuthorizationRequest) -> ResourceAuthorizationResult: ...


class ProcessAuthorizer(Protocol):
    def authorize(self, request: ProcessAuthorizationRequest) -> ProcessAuthorizationResult: ...


class DatabaseAuthorizer(Protocol):
    def authorize(
        self,
        request: DatabaseAuthorizationRequest,
        *,
        verified_agent_id: str | None = None,
    ) -> ResourceAuthorizationResult: ...


class APIAuthorizer(Protocol):
    def authorize(
        self,
        request: APIAuthorizationRequest,
        *,
        verified_agent_id: str | None = None,
    ) -> ResourceAuthorizationResult: ...
