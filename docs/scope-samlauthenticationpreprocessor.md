# Scoping SpidSamlAuthenticationPreprocessor to SPID-only flows

## Problem

`SamlAuthenticationPreprocessor` is a global Keycloak SPI. Every registered implementation is
invoked for **all** SAML flows in the realm, regardless of which identity provider initiated them.
`SpidSamlAuthenticationPreprocessor` was therefore also running for standard OOTB SAML IDPs,
applying SPID-specific mutations (Issuer `NameQualifier`/`Format`, `NameIDPolicy SPNameQualifier`)
to requests that have nothing to do with SPID.

## Why client notes are safe to use

`AuthenticationSessionModel.setClientNote()` and `UserSessionModel.setNote()` are internal
Keycloak state — key-value pairs stored in the session database. They are never serialised into
SAML requests, responses, or assertions. The existing code already used this pattern
(`SPID_REQUEST_ISSUE_INSTANT` is stored as a client note for response validation).

## Solution

A lightweight marker flag is set on the session at the entry points owned by `SpidIdentityProvider`,
before control is handed to the base class. The preprocessor reads the flag and no-ops if it is
absent.

### Login flow

`SpidIdentityProvider.performLogin()` sets the flag on the `AuthenticationSessionModel` before
delegating to `SAMLIdentityProvider.performLogin()`. The preprocessor's
`beforeSendingLoginRequest()` reads it via `authSession.getClientNote(SPID_FLOW_MARKER)`.

### Logout flows

Both browser-initiated and backchannel logout are covered:

- `SpidIdentityProvider.keycloakInitiatedBrowserLogout()` sets the flag on `UserSessionModel`
- `SpidIdentityProvider.backchannelLogout()` does the same

The preprocessor's `beforeSendingLogoutRequest()` reads it via
`userSession.getNote(SPID_FLOW_MARKER)`. The note is benign on the user session because logout
destroys the session immediately after.

### Constant

`SpidIdentityProvider.SPID_FLOW_MARKER = "SPID_FLOW"` is the single source of truth used by
both sides.

## Files changed

| File | Change |
|------|--------|
| `SpidIdentityProvider.java` | Added `SPID_FLOW_MARKER` constant; overrides for `performLogin`, `keycloakInitiatedBrowserLogout`, `backchannelLogout` |
| `SpidSamlAuthenticationPreprocessor.java` | Early-return guard at the top of `beforeSendingLoginRequest` and `beforeSendingLogoutRequest` |

## Alternatives considered

**Check IDP type via realm model** — `authSession.getParentSession().getRealm()` exposes
`getIdentityProvidersStream()`, but the IDP alias is not directly available from the auth session,
making this fragile and dependent on Keycloak internals.

**Check request issuer against a known SPID registry** — parsing the issuer URL and comparing it
against configuration would work but requires maintenance as SP entity IDs change.

The marker approach was chosen because it is explicit, zero-overhead, follows the existing
`SPID_REQUEST_ISSUE_INSTANT` pattern already in the codebase, and requires no access to Keycloak
internals beyond the public session API.
