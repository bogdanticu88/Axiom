import unittest
from datetime import datetime, timedelta, timezone
from platform_core.cases import Case, State, ClosureEvidence, Conflict
from platform_core.access import Grant, require_permission


class DomainTests(unittest.TestCase):
    def test_cannot_skip_investigation(self):
        with self.assertRaises(Conflict):
            Case('a', 'case').transition(State.CLOSED, 0)

    def test_stale_writer_rejected(self):
        c = Case('a', 'case').transition(State.INVESTIGATING, 0)
        with self.assertRaises(Conflict):
            c.transition(State.REVIEW, 0)

    def test_verified_closure_requires_correct_deployment(self):
        c = Case('a', 'case', State.VERIFYING)
        with self.assertRaises(Conflict):
            c.transition(State.CLOSED, 0, ClosureEvidence(
                'verified_remediated', True, verification_passed=True))

    def test_closure_and_reopening_preserve_original(self):
        c = Case('a', 'case', State.VERIFYING)
        closed = c.transition(State.CLOSED, 0, ClosureEvidence(
            'verified_remediated', True, True, True))
        reopened = closed.transition(State.INVESTIGATING, 1)
        self.assertEqual(c.state, State.VERIFYING)
        self.assertEqual(closed.state, State.CLOSED)
        self.assertEqual(reopened.version, 2)

    def test_ticket_closure_is_not_valid_evidence(self):
        with self.assertRaises(Conflict):
            Case('a', 'case', State.REVIEW).transition(
                State.CLOSED, 0, ClosureEvidence('ticket_closed', True))

    def test_risk_acceptance_requires_authority(self):
        for authority, active in [(False, True), (True, False)]:
            with self.assertRaises(Conflict):
                Case('a', 'case', State.REVIEW).transition(State.CLOSED, 0,
                    ClosureEvidence('accepted_risk', authority, acceptance_active=active))

    def test_permissions_cannot_cross_boundaries(self):
        now = datetime.now(timezone.utc)
        grant = Grant('a', 'user', 'case.read', 'project', now + timedelta(hours=1))
        base = dict(tenant_id='a', principal_id='user', permission='case.read',
                    scope_id='project', now=now)
        require_permission((grant,), **base)
        for key, value in [('tenant_id', 'b'), ('principal_id', 'other'),
                           ('permission', 'risk.accept'), ('scope_id', 'other')]:
            with self.assertRaises(PermissionError):
                require_permission((grant,), **(base | {key: value}))

    def test_expired_and_revoked_grants_denied(self):
        now = datetime.now(timezone.utc)
        for expiry, revoked in [(now, False), (now + timedelta(hours=1), True)]:
            with self.assertRaises(PermissionError):
                require_permission((Grant('a', 'u', 'case.read', 's', expiry, revoked),),
                    tenant_id='a', principal_id='u', permission='case.read', scope_id='s', now=now)


if __name__ == '__main__':
    unittest.main()
