-- 0009 Per-effect-class action permissions (ACT-08).
--
-- Proposing, approving and executing are separate permissions for each effect class. Checks match the exact class:
-- there is no hierarchy, so a permission for a weaker class (ticket.create) never authorises a stronger one
-- (pull_request.create, production.change). The generic action.propose / action.approve / action.execute permissions
-- remain in the catalogue for history but are no longer granted to roles and no longer checked.

INSERT INTO axiom.permissions(permission, privileged, description) VALUES
 ('action.propose:ticket_create', false, 'Propose ticket creation'),
 ('action.approve:ticket_create', true, 'Approve ticket creation'),
 ('action.execute:ticket_create', false, 'Request execution of approved ticket creation'),
 ('action.propose:pull_request_create', false, 'Propose pull request creation'),
 ('action.approve:pull_request_create', true, 'Approve pull request creation'),
 ('action.execute:pull_request_create', false, 'Request execution of approved pull request creation'),
 ('action.propose:production_change', true, 'Propose a production change'),
 ('action.approve:production_change', true, 'Approve a production change'),
 ('action.execute:production_change', true, 'Request execution of an approved production change');

INSERT INTO axiom.roles(id, description) VALUES
 ('change_approver', 'Approve pull request creation within delegated scope'),
 ('production_change_requester', 'Propose and request execution of production changes (disabled by default)'),
 ('production_change_approver', 'Approve production changes (disabled by default)');

DELETE FROM axiom.role_permissions WHERE permission IN ('action.propose', 'action.approve', 'action.execute');
INSERT INTO axiom.role_permissions(role_id, permission) VALUES
 ('analyst', 'action.propose:ticket_create'), ('analyst', 'action.execute:ticket_create'),
 ('analyst', 'action.propose:pull_request_create'), ('analyst', 'action.execute:pull_request_create'),
 ('approver', 'action.approve:ticket_create'),
 ('change_approver', 'proposal.read'), ('change_approver', 'case.read'),
 ('change_approver', 'action.approve:pull_request_create'),
 ('production_change_requester', 'case.read'), ('production_change_requester', 'proposal.read'),
 ('production_change_requester', 'action.propose:production_change'),
 ('production_change_requester', 'action.execute:production_change'),
 ('production_change_approver', 'case.read'), ('production_change_approver', 'proposal.read'),
 ('production_change_approver', 'action.approve:production_change');
