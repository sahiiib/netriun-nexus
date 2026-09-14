# Single sign-on

Netriun Nexus supports workspace-scoped OpenID Connect (OIDC) and SAML 2.0 identity providers. Authentication establishes a Nexus identity; the Access Policy engine still decides which cloud accounts and operations that identity can use.

## Safety model

- OIDC identities are linked by the configured issuer and the verified `sub` claim.
- SAML identities are linked by the configured IdP and a persistent NameID from a validated, signed assertion.
- Email is required for account linking and JIT provisioning, but an unverified OIDC email is never trusted.
- Manual team memberships and SSO-derived memberships are stored separately. SSO reconciliation cannot delete a manual grant.
- Workspace Owner local login is always available as break-glass access, even when SSO is required.
- Provider secrets, SAML IdP metadata, and the generated SAML SP private key are encrypted at rest.

## Configure OIDC

1. In the identity provider, create a confidential web application.
2. Set the redirect URI to `https://nexus.netriun.com/sso/PROVIDER_ID/callback`. Nexus shows the exact sign-in URL after the provider is saved; the callback uses the same provider identifier.
3. In **Workspace settings → OIDC & SAML providers**, add an OIDC provider with its HTTPS issuer, client ID, client secret, and scopes.
4. Map the email, username, and groups claim names. Defaults are `email`, `preferred_username`, and `groups`.
5. Enable the provider. Nexus uses Authorization Code flow with state, nonce, PKCE S256, discovery, signature verification, issuer validation, and audience validation.

## Configure SAML 2.0

1. Export the IdP metadata XML and add a SAML provider in Workspace settings.
2. Save the provider, then copy the generated **SP metadata URL** into the IdP application.
3. Configure the IdP to return a persistent NameID, an email attribute, an optional username attribute, and the group attribute.
4. The default Assertion Consumer Service is `https://nexus.netriun.com/sso/PROVIDER_ID/acs` and uses HTTP-POST.
5. Enable the provider after the IdP trusts the generated SP certificate and metadata.

## Map IdP groups to access

1. Create the Nexus teams and assign those teams Viewer, Operator, or Account Manager access to cloud accounts.
2. Open **Group mappings** on the identity provider.
3. Enter the exact group claim/attribute value, choose the Nexus team, and choose a membership role cap.
4. On each SSO login, Nexus replaces only that provider's SSO-derived memberships for the user. Removed IdP groups therefore stop granting access without affecting manual memberships.

## JIT provisioning and enforcement

JIT provisioning creates a normal workspace user after a successful, verified SSO login if no user with that verified email exists. The Community workspace user limit still applies. Keep JIT disabled when every user must be pre-provisioned.

Only require SSO after at least one provider has been tested. Nexus prevents disabling or deleting the last enabled provider while enforcement is active. Distribute the workspace SSO code or the provider's direct sign-in URL to users.
