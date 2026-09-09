from enum import StrEnum


class DecisionAction(StrEnum):
    ALLOW = "ALLOW"
    LOG = "LOG"
    SANITIZE = "SANITIZE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"
    TERMINATE = "TERMINATE"


ACTION_PRECEDENCE: tuple[DecisionAction, ...] = (
    DecisionAction.TERMINATE,
    DecisionAction.QUARANTINE,
    DecisionAction.DENY,
    DecisionAction.APPROVAL_REQUIRED,
    DecisionAction.SANITIZE,
    DecisionAction.LOG,
    DecisionAction.ALLOW,
)

