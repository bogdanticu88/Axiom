from dataclasses import dataclass, replace
from enum import StrEnum


class Conflict(ValueError):
    pass


class State(StrEnum):
    RECEIVED = 'received'
    INVESTIGATING = 'investigating'
    REVIEW = 'review_required'
    PLANNED = 'remediation_planned'
    REMEDIATING = 'remediating'
    VERIFYING = 'awaiting_verification'
    CLOSED = 'closed'


ALLOWED = {
    State.RECEIVED: {State.INVESTIGATING},
    State.INVESTIGATING: {State.REVIEW},
    State.REVIEW: {State.INVESTIGATING, State.PLANNED, State.CLOSED},
    State.PLANNED: {State.REMEDIATING},
    State.REMEDIATING: {State.VERIFYING},
    State.VERIFYING: {State.CLOSED, State.REMEDIATING, State.REVIEW},
    State.CLOSED: {State.INVESTIGATING},
}


@dataclass(frozen=True)
class ClosureEvidence:
    """Trusted guard inputs loaded by the future persistence service, never client flags."""
    reason: str
    authorised: bool
    verification_passed: bool = False
    deployment_matches: bool = False
    acceptance_active: bool = False
    dismissal_supported: bool = False
    duplicate_validated: bool = False

    def valid(self) -> bool:
        return self.authorised and {
            'verified_remediated': self.verification_passed and self.deployment_matches,
            'accepted_risk': self.acceptance_active,
            'dismissed': self.dismissal_supported,
            'duplicate': self.duplicate_validated,
        }.get(self.reason, False)


@dataclass(frozen=True)
class Case:
    tenant_id: str
    id: str
    state: State = State.RECEIVED
    version: int = 0

    def transition(self, target: State, expected_version: int,
                   closure: ClosureEvidence | None = None) -> 'Case':
        if expected_version != self.version:
            raise Conflict('stale case version')
        if target not in ALLOWED[self.state]:
            raise Conflict('unsupported transition')
        if target == State.CLOSED:
            if closure is None or not closure.valid():
                raise Conflict('closure evidence or authority missing')
            if self.state == State.VERIFYING and closure.reason != 'verified_remediated':
                raise Conflict('other dispositions require review')
            if self.state == State.REVIEW and closure.reason == 'verified_remediated':
                raise Conflict('verified closure requires verification workflow')
        return replace(self, state=target, version=self.version + 1)
