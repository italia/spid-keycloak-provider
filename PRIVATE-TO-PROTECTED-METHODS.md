  1. getIDPKeyLocator()

  - Referenced at: Lines 176, 195
  - Called by: Both SpidPostBinding.validateAssertionSignature() and SpidRedirectBinding.validateAssertionSignature()
  - Purpose: Returns the key locator needed for assertion signature validation

  2. containsUnencryptedSignature(SAMLDocumentHolder)

  - Referenced at: Lines 177, 196
  - Called by: Both SpidPostBinding.validateAssertionSignature() and SpidRedirectBinding.validateAssertionSignature()
  - Purpose: Checks whether the SAML document holder contains an unencrypted signature

  3. samlIdpInitiatedSSO(String clientUrlName, EventBuilder event)

  - Referenced at: Line 216
  - Currently duplicated: Lines 401-425 (entire method copied because it's private in parent)
  - Comment at line 399: "This method is private in the parent SAMLEndpoint, so we need our own copy."
  - Purpose: Handles SAML IDP-initiated SSO flow

  Analysis Notes

  - The helper methods visible from line 427 onwards (like getSubjectNameID, getPrincipal, validateInResponseToAttribute, etc.) are SPID-specific
  implementations in SpidSAMLEndpoint itself, not calls to parent methods.
  - Fields like realm, callback, and provider appear to already be protected in the parent (based on usage at lines 211, 218, 380).
  - Making just these 3 methods protected would eliminate the code duplication at lines 401-425 and enable proper inheritance for the binding subclasses.
