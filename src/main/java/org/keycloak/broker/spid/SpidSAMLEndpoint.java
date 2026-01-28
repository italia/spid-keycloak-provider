/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.broker.spid;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.protocol.saml.SamlPrincipalType;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlService;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.saml.processing.core.saml.v2.constants.X500SAMLProfileConstants;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.validators.ConditionsValidator;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import javax.xml.namespace.QName;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * SPID-specific SAML endpoint that extends the standard SAMLEndpoint
 * with SPID response validation rules.
 */
public class SpidSAMLEndpoint extends SAMLEndpoint {
    protected static final Logger logger = Logger.getLogger(SpidSAMLEndpoint.class);

    // Store references to parent's private fields that we need to access
    private final KeycloakSession session;
    private final SpidIdentityProviderConfig spidConfig;
    private final DestinationValidator destinationValidator;
    private final ClientConnection clientConnection;

    // SPID validation helper
    private final SpidChecks spidChecks;

    public SpidSAMLEndpoint(KeycloakSession session, SpidIdentityProvider provider,
                           SpidIdentityProviderConfig config,
                           SAMLIdentityProvider.AuthenticationCallback callback,
                           DestinationValidator destinationValidator) {
        super(session, provider, config, callback, destinationValidator);
        // Store references to parent's private fields for local access
        this.session = session;
        this.spidConfig = config;
        this.destinationValidator = destinationValidator;
        this.clientConnection = session.getContext().getConnection();
        this.spidChecks = new SpidChecks(config);
    }

    @GET
    @Override
    public Response redirectBinding(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                    @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                    @QueryParam(GeneralConstants.SAML_ARTIFACT_KEY) String samlArt,
                                    @QueryParam(GeneralConstants.RELAY_STATE) String relayState) {
        return new SpidRedirectBinding().execute(samlRequest, samlResponse, samlArt, relayState, null);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Override
    public Response postBinding(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                @FormParam(GeneralConstants.SAML_ARTIFACT_KEY) String samlArt,
                                @FormParam(GeneralConstants.RELAY_STATE) String relayState) {
        return new SpidPostBinding().execute(samlRequest, samlResponse, samlArt, relayState, null);
    }

    @Path("clients/{client_id}")
    @GET
    @Override
    public Response redirectBindingIdpInitiated(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                                @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                                @QueryParam(GeneralConstants.RELAY_STATE) String relayState,
                                                @PathParam("client_id") String clientId) {
        return new SpidRedirectBinding().execute(samlRequest, samlResponse, null, relayState, clientId);
    }

    @Path("clients/{client_id}")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Override
    public Response postBindingIdpInitiated(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                           @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                           @FormParam(GeneralConstants.RELAY_STATE) String relayState,
                                           @PathParam("client_id") String clientId) {
        return new SpidPostBinding().execute(samlRequest, samlResponse, null, relayState, clientId);
    }

    /**
     * SPID-specific POST binding that overrides handleLoginResponse with SPID validation.
     */
    protected class SpidPostBinding extends PostBinding {
        @Override
        protected Response handleLoginResponse(String samlResponse, SAMLDocumentHolder holder,
                                               ResponseType responseType, String relayState, String clientId) {
            return handleSpidLoginResponse(this::validateAssertionSignature, samlResponse, holder, responseType, relayState, clientId);
        }

        private boolean validateAssertionSignature(Element assertionElement, SAMLDocumentHolder holder) {
            return validateAssertionSignatureImpl(
                assertionElement,
                getIDPKeyLocator(),
                containsUnencryptedSignature(holder)
            );
        }
    }

    /**
     * SPID-specific Redirect binding that overrides handleLoginResponse with SPID validation.
     */
    protected class SpidRedirectBinding extends RedirectBinding {
        @Override
        protected Response handleLoginResponse(String samlResponse, SAMLDocumentHolder holder,
                                               ResponseType responseType, String relayState, String clientId) {
            return handleSpidLoginResponse(this::validateAssertionSignature, samlResponse, holder, responseType, relayState, clientId);
        }

        private boolean validateAssertionSignature(Element assertionElement, SAMLDocumentHolder holder) {
            return validateAssertionSignatureImpl(
                assertionElement,
                getIDPKeyLocator(),
                containsUnencryptedSignature(holder)
            );
        }
    }

    /**
     * Handles the SAML login response with SPID-specific validation rules.
     * This is the core SPID-specific logic that differs from the parent SAMLEndpoint.
     *
     * @param signatureValidator function to validate assertion signature (provided by binding subclass)
     */
    protected Response handleSpidLoginResponse(
            java.util.function.BiFunction<Element, SAMLDocumentHolder, Boolean> signatureValidator,
            String samlResponse, SAMLDocumentHolder holder,
            ResponseType responseType, String relayState, String clientId) {
        EventBuilder event = new EventBuilder(realm, session, clientConnection);

        try {
            AuthenticationSessionModel authSession;
            if (StringUtil.isNotBlank(clientId)) {
                authSession = samlIdpInitiatedSSO(clientId, event);
            } else if (StringUtil.isNotBlank(relayState)) {
                authSession = callback.getAndVerifyAuthenticationSession(relayState);
            } else {
                logger.error("SAML RelayState parameter was null when it should be returned by the IDP");
                event.event(EventType.LOGIN);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
            session.getContext().setAuthenticationSession(authSession);

            KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);

            // SPID-specific: Handle error responses with SPID error code translation
            if (!isSuccessfulSamlResponse(responseType)) {
                if (spidChecks.isSpidFault(responseType)) {
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR);
                    event.error(Errors.INVALID_SAML_RESPONSE);
                    return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST,
                        spidChecks.formatSpidFaultMessage(responseType.getStatus().getStatusMessage()));
                } else {
                    String statusMessage = responseType.getStatus() == null || responseType.getStatus().getStatusMessage() == null
                        ? Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR
                        : responseType.getStatus().getStatusMessage();
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR);
                    event.error(Errors.INVALID_SAML_RESPONSE);
                    return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, statusMessage);
                }
            }

            if (responseType.getAssertions() == null || responseType.getAssertions().isEmpty()) {
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }

            boolean assertionIsEncrypted = AssertionUtil.isAssertionEncrypted(responseType);

            if (spidConfig.isWantAssertionsEncrypted() && !assertionIsEncrypted) {
                logger.error("The assertion is not encrypted, which is required.");
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
            }

            Element assertionElement;
            if (assertionIsEncrypted) {
                assertionElement = AssertionUtil.decryptAssertion(responseType, keys.getPrivateKey());
            } else {
                assertionElement = DocumentUtil.getElement(holder.getSamlDocument(), new QName(JBossSAMLConstants.ASSERTION.get()));
            }

            // SPID-specific: Apply SPID response validation rules
            String spidResponseValidationError = spidChecks.validateSpidResponse(authSession, holder, assertionElement);

            if (spidResponseValidationError != null) {
                logger.error("SPID Response Validation Error: " + spidResponseValidationError);
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST,
                    spidConfig.isDebugEnabled() ? spidResponseValidationError : "SpidSamlCheck_GenericError");
            }

            // Validate the response Issuer
            final String responseIssuer = responseType.getIssuer() != null ? responseType.getIssuer().getValue() : null;
            if (spidConfig.getIdpEntityId() != null && !spidConfig.getIdpEntityId().equals(responseIssuer)) {
                logger.errorf("Response Issuer validation failed: expected %s, actual %s", spidConfig.getIdpEntityId(), responseIssuer);
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
            }

            // Validate InResponseTo attribute
            String expectedRequestId = authSession.getClientNote(SamlProtocol.SAML_REQUEST_ID_BROKER);
            if (!validateInResponseToAttribute(responseType, expectedRequestId)) {
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
            }

            // Validate assertion signature
            if (!signatureValidator.apply(assertionElement, holder)) {
                logger.error("validation failed");
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SIGNATURE);
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
            }

            if (AssertionUtil.isIdEncrypted(responseType)) {
                AssertionUtil.decryptId(responseType, data -> Collections.singletonList(keys.getPrivateKey()));
            }

            AssertionType assertion = responseType.getAssertions().get(0).getAssertion();

            // Validate the assertion Issuer
            final String assertionIssuer = assertion.getIssuer() != null ? assertion.getIssuer().getValue() : null;
            if (spidConfig.getIdpEntityId() != null && !spidConfig.getIdpEntityId().equals(assertionIssuer)) {
                logger.errorf("Assertion Issuer validation failed: expected %s, actual %s", spidConfig.getIdpEntityId(), assertionIssuer);
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
            }

            NameIDType subjectNameID = getSubjectNameID(assertion);
            String principal = getPrincipal(assertion);

            if (principal == null) {
                logger.errorf("no principal in assertion; expected: %s", expectedPrincipalType());
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
            }

            BrokeredIdentityContext identity = new BrokeredIdentityContext(principal, spidConfig);
            identity.getContextData().put(SAML_LOGIN_RESPONSE, responseType);
            identity.getContextData().put(SAML_ASSERTION, assertion);
            identity.setAuthenticationSession(authSession);
            identity.setUsername(principal);

            if (subjectNameID != null && subjectNameID.getFormat() != null &&
                subjectNameID.getFormat().toString().equals(JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get())) {
                identity.setEmail(subjectNameID.getValue());
            }

            if (spidConfig.isStoreToken()) {
                identity.setToken(samlResponse);
            }

            ConditionsValidator.Builder cvb = new ConditionsValidator.Builder(
                assertion.getID(), assertion.getConditions(), destinationValidator)
                .clockSkewInMillis(1000 * spidConfig.getAllowedClockSkew());
            try {
                String issuerURL = getEntityId();
                cvb.addAllowedAudience(URI.create(issuerURL));
                if (responseType.getDestination() != null) {
                    cvb.addAllowedAudience(URI.create(responseType.getDestination()));
                }
            } catch (IllegalArgumentException ex) {
                // warning has been already emitted
            }

            if (!cvb.build().isValid()) {
                logger.error("Assertion expired.");
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.EXPIRED_CODE);
            }

            AuthnStatementType authn = null;
            for (Object statement : assertion.getStatements()) {
                if (statement instanceof AuthnStatementType) {
                    authn = (AuthnStatementType) statement;
                    identity.getContextData().put(SAML_AUTHN_STATEMENT, authn);
                    break;
                }
            }

            if (assertion.getAttributeStatements() != null) {
                String email = getX500Attribute(assertion, X500SAMLProfileConstants.EMAIL);
                if (email != null) {
                    identity.setEmail(email);
                }
            }

            String brokerUserId = spidConfig.getAlias() + "." + principal;
            identity.setBrokerUserId(brokerUserId);
            identity.setIdp(provider); // parent's protected provider field

            if (authn != null && authn.getSessionIndex() != null) {
                identity.setBrokerSessionId(spidConfig.getAlias() + "." + authn.getSessionIndex());
            }

            return callback.authenticated(identity);

        } catch (WebApplicationException e) {
            return e.getResponse();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not process response from SAML identity provider.", e);
        }
    }

    // ============== Private method copied from parent (it's private in SAMLEndpoint) ==============

    /**
     * Handles SAML IDP-initiated SSO.
     * This method is private in the parent SAMLEndpoint, so we need our own copy.
     */
    private AuthenticationSessionModel samlIdpInitiatedSSO(final String clientUrlName, EventBuilder event) {
        event.event(EventType.LOGIN);
        CacheControlUtil.noBackButtonCacheControlHeader(session);
        Optional<ClientModel> oClient = session.clients()
            .searchClientsByAttributes(realm, Collections.singletonMap(SamlProtocol.SAML_IDP_INITIATED_SSO_URL_NAME, clientUrlName), 0, 1)
            .findFirst();

        if (!oClient.isPresent()) {
            event.error(Errors.CLIENT_NOT_FOUND);
            Response response = ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.CLIENT_NOT_FOUND);
            throw new WebApplicationException(response);
        }

        LoginProtocolFactory factory = (LoginProtocolFactory) session.getKeycloakSessionFactory()
            .getProviderFactory(LoginProtocol.class, SamlProtocol.LOGIN_PROTOCOL);
        SamlService samlService = (SamlService) factory.createProtocolEndpoint(session, event);
        AuthenticationSessionModel authSession = samlService.getOrCreateLoginSessionForIdpInitiatedSso(session, realm, oClient.get(), null);
        if (authSession == null) {
            event.error(Errors.INVALID_REDIRECT_URI);
            Response response = ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REDIRECT_URI);
            throw new WebApplicationException(response);
        }

        return authSession;
    }

    // ============== Helper methods for handleSpidLoginResponse ==============

    /**
     * Validates assertion signatures. This is the shared implementation used by both binding types.
     *
     * @param assertionElement the assertion element to validate
     * @param keyLocator key locator for signature validation (from binding's protected method)
     * @param hasUnencryptedSignature whether holder contains unencrypted signature (from binding's protected method)
     */
    private boolean validateAssertionSignatureImpl(Element assertionElement,
                                                   org.keycloak.rotation.KeyLocator keyLocator,
                                                   boolean hasUnencryptedSignature) {
        boolean signed = AssertionUtil.isSignedElement(assertionElement);
        final boolean assertionSignatureNotExistsWhenRequired = spidConfig.isWantAssertionsSigned() && !signed;
        final boolean signatureNotValid = signed && spidConfig.isValidateSignature() && !AssertionUtil.isSignatureValid(assertionElement, keyLocator);
        final boolean hasNoSignatureWhenRequired = !signed && spidConfig.isValidateSignature() && !hasUnencryptedSignature;

        return !(assertionSignatureNotExistsWhenRequired || signatureNotValid || hasNoSignatureWhenRequired);
    }

    private boolean isSuccessfulSamlResponse(ResponseType responseType) {
        return responseType != null
            && responseType.getStatus() != null
            && responseType.getStatus().getStatusCode() != null
            && responseType.getStatus().getStatusCode().getValue() != null
            && !responseType.getStatus().getStatusCode().getValue().toString().isEmpty()
            && Objects.equals(responseType.getStatus().getStatusCode().getValue().toString(),
                              JBossSAMLURIConstants.STATUS_SUCCESS.get());
    }

    private String getEntityId() {
        String configEntityId = spidConfig.getEntityId();
        if (configEntityId == null || configEntityId.isEmpty()) {
            return UriBuilder.fromUri(session.getContext().getUri().getBaseUri())
                .path("realms").path(realm.getName()).build().toString();
        }
        return configEntityId;
    }

    private NameIDType getSubjectNameID(final AssertionType assertion) {
        SubjectType subject = assertion.getSubject();
        SubjectType.STSubType subType = subject.getSubType();
        return subType != null ? (NameIDType) subType.getBaseID() : null;
    }

    private String getPrincipal(AssertionType assertion) {
        SamlPrincipalType principalType = spidConfig.getPrincipalType();
        if (principalType == null || principalType.equals(SamlPrincipalType.SUBJECT)) {
            NameIDType subjectNameID = getSubjectNameID(assertion);
            return subjectNameID != null ? subjectNameID.getValue() : null;
        } else if (principalType.equals(SamlPrincipalType.ATTRIBUTE)) {
            return getAttributeByName(assertion, spidConfig.getPrincipalAttribute());
        } else {
            return getAttributeByFriendlyName(assertion, spidConfig.getPrincipalAttribute());
        }
    }

    private String expectedPrincipalType() {
        SamlPrincipalType principalType = spidConfig.getPrincipalType();
        switch (principalType) {
            case SUBJECT:
                return principalType.name();
            case ATTRIBUTE:
            case FRIENDLY_ATTRIBUTE:
                return String.format("%s(%s)", principalType.name(), spidConfig.getPrincipalAttribute());
            default:
                return null;
        }
    }

    private String getX500Attribute(AssertionType assertion, X500SAMLProfileConstants attribute) {
        return getFirstMatchingAttribute(assertion, attribute::correspondsTo);
    }

    private String getAttributeByName(AssertionType assertion, String name) {
        return getFirstMatchingAttribute(assertion, attribute -> Objects.equals(attribute.getName(), name));
    }

    private String getAttributeByFriendlyName(AssertionType assertion, String friendlyName) {
        return getFirstMatchingAttribute(assertion, attribute -> Objects.equals(attribute.getFriendlyName(), friendlyName));
    }

    private String getFirstMatchingAttribute(AssertionType assertion, Predicate<AttributeType> predicate) {
        return assertion.getAttributeStatements().stream()
            .map(AttributeStatementType::getAttributes)
            .flatMap(Collection::stream)
            .map(AttributeStatementType.ASTChoiceType::getAttribute)
            .filter(predicate)
            .map(AttributeType::getAttributeValue)
            .flatMap(Collection::stream)
            .findFirst()
            .map(Object::toString)
            .orElse(null);
    }

    private boolean validateInResponseToAttribute(ResponseType responseType, String expectedRequestId) {
        if (expectedRequestId == null || expectedRequestId.isEmpty()) {
            return true;
        }

        if (responseType.getInResponseTo() == null) {
            logger.error("Response Validation Error: InResponseTo attribute was expected but not present in received response");
            return false;
        }

        String responseInResponseToValue = responseType.getInResponseTo();
        if (responseInResponseToValue.isEmpty()) {
            logger.error("Response Validation Error: InResponseTo attribute was expected but it is empty in received response");
            return false;
        }

        if (!responseInResponseToValue.equals(expectedRequestId)) {
            logger.error("Response Validation Error: received InResponseTo attribute does not match the expected request ID");
            return false;
        }

        if (responseType.getAssertions().isEmpty()) {
            return true;
        }

        SubjectType subjectElement = responseType.getAssertions().get(0).getAssertion().getSubject();
        if (subjectElement != null && subjectElement.getConfirmation() != null && !subjectElement.getConfirmation().isEmpty()) {
            var subjectConfirmationElement = subjectElement.getConfirmation().get(0);
            if (subjectConfirmationElement != null) {
                var subjectConfirmationDataElement = subjectConfirmationElement.getSubjectConfirmationData();
                if (subjectConfirmationDataElement != null && subjectConfirmationDataElement.getInResponseTo() != null) {
                    String subjectConfirmationDataInResponseToValue = subjectConfirmationDataElement.getInResponseTo();
                    if (subjectConfirmationDataInResponseToValue.isEmpty()) {
                        logger.error("Response Validation Error: SubjectConfirmationData InResponseTo attribute was expected but it is empty in received response");
                        return false;
                    }
                    if (!subjectConfirmationDataInResponseToValue.equals(expectedRequestId)) {
                        logger.error("Response Validation Error: received SubjectConfirmationData InResponseTo attribute does not match the expected request ID");
                        return false;
                    }
                }
            }
        }
        return true;
    }

}
