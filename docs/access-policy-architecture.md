# Access policy architecture

This document records the approved authorization architecture for Netriun Nexus. Authentication and authorization remain separate: local passwords, OIDC, and SAML establish identity; this policy model decides what that identity may do.

## Authorization rule

Every non-administrator user is denied by default. Access is granted explicitly for a cloud account, with a role that defines the allowed capabilities. A user may therefore be a Viewer in one account, an Operator in another, and have no access to a third.

Workspace Owner and Workspace Administrator are workspace-level roles. They are intentionally separate from account roles.

## Core objects

- **Principal:** a Nexus user or team.
- **Role:** a named set of capabilities. Built-in roles are Viewer, Operator, and Account Manager.
- **Assignment:** connects a principal, role, cloud account, and optional service scope.
- **Membership grant:** connects a user to a team and records whether the source is manual or SSO.
- **Effective access:** the union of applicable direct and team assignments, always constrained to the current workspace.

Initial capabilities include `account.view`, `account.manage`, `compute.view`, `compute.operate`, `eds.view`, `eds.operate`, and `eds.manage`. Capability names are service-oriented so future services can add permissions without adding boolean columns.

## Account and service scope

An assignment with `service_key = '*'` applies to the cloud account. Later service-specific assignments may use stable keys such as `ec2`, `s3`, `eds`, or `vpc`. The initial UI will manage account-level assignments while the storage model remains ready for service-level scope.

Direct user assignments and team assignments are both supported. For a team assignment, the user's team membership role caps the assignment role. This prevents a Viewer membership from inheriting Operator actions through a more privileged team assignment.

## Migration behavior

The `account_access_assignments` table is introduced without changing current users' access. For an account with no new assignments, the legacy `cloud_accounts.group_id`, access-group flags, and `user_groups.role` remain authoritative. As soon as an account receives an explicit assignment, the new policy model becomes authoritative for that account.

This account-by-account fallback must remain until the Access Policy UI can migrate and verify all existing assignments.

## SSO integration

OIDC and SAML group mappings will create source-aware team membership grants. SSO grants must not overwrite manual grants. Removing an IdP group membership removes only the matching SSO grant.

External identities are linked by provider identity (`issuer + subject` for OIDC and IdP + persistent NameID for SAML), never by an unverified email alone. The workspace owner retains a local break-glass login even when SSO enforcement is enabled.

## Policy evaluation

All resource endpoints call the central policy engine with a capability and resource context. Evaluation checks workspace isolation, direct assignments, team assignments, membership-role caps, and resource scope. Mutation endpoints continue to record intent in the audit log before calling a cloud provider.

Explicit deny rules are not part of the first version. Grants are additive and the UI must show the effective role and every source that contributed to it.
