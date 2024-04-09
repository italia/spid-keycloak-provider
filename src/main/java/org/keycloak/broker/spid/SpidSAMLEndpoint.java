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

import java.util.Arrays;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.VerificationException;
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.protocol.saml.SAMLDecryptionKeysLocator;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlProtocolUtils;
import org.keycloak.protocol.saml.SamlService;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.SAMLRequestParser;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.processing.core.util.XMLEncryptionUtil;
import org.keycloak.saml.processing.web.util.PostBindingUtil;
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
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SpidSAMLEndpoint extends SAMLEndpoint {
    protected static final Logger logger = Logger.getLogger(SpidSAMLEndpoint.class);
    public static final String SAML_FEDERATED_SESSION_INDEX = "SAML_FEDERATED_SESSION_INDEX";
    @Deprecated // in favor of SAML_FEDERATED_SUBJECT_NAMEID
    public static final String SAML_FEDERATED_SUBJECT = "SAML_FEDERATED_SUBJECT";
    @Deprecated // in favor of SAML_FEDERATED_SUBJECT_NAMEID
    public static final String SAML_FEDERATED_SUBJECT_NAMEFORMAT = "SAML_FEDERATED_SUBJECT_NAMEFORMAT";
    public static final String SAML_FEDERATED_SUBJECT_NAMEID = "SAML_FEDERATED_SUBJECT_NAME_ID";
    public static final String SAML_LOGIN_RESPONSE = "SAML_LOGIN_RESPONSE";
    public static final String SAML_ASSERTION = "SAML_ASSERTION";
    public static final String SAML_AUTHN_STATEMENT = "SAML_AUTHN_STATEMENT";
    protected RealmModel realm;
    protected EventBuilder event;
    protected SpidIdentityProviderConfig config;
    protected IdentityProvider.AuthenticationCallback callback;
    protected SpidIdentityProvider provider;
    // iso8601 fully compliant regex
    private static final String _UTC_STRING = "^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$";
    //
    private static final String[] SPID_LEVEL= {"https://www.spid.gov.it/SpidL1", "https://www.spid.gov.it/SpidL2", "https://www.spid.gov.it/SpidL3"};
    
    @Context
    private KeycloakSession session;

    @Context
    private ClientConnection clientConnection;

    @Context
    private HttpHeaders headers;


    public SpidSAMLEndpoint(KeycloakSession session, SpidIdentityProvider provider, SpidIdentityProviderConfig config, IdentityProvider.AuthenticationCallback callback, DestinationValidator destinationValidator) {
        super(session, provider, config, callback, destinationValidator);
        this.realm = session.getContext().getRealm();
        this.config = config;
        this.callback = callback;
        this.provider = provider;
        this.session = session;
        this.clientConnection = session.getContext().getConnection();
        this.headers = session.getContext().getRequestHeaders();
    }

    @GET
    @NoCache
    @Path("descriptor")
    public Response getSPDescriptor() {
        return provider.export(session.getContext().getUri(), realm, null);
    }

    @GET
    public Response redirectBinding(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                    @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                    @QueryParam(GeneralConstants.RELAY_STATE) String relayState)  {
        return new SpidRedirectBinding().execute(samlRequest, samlResponse, relayState, null);
    }


    /**
     */
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response postBinding(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                @FormParam(GeneralConstants.RELAY_STATE) String relayState) {
        return new SpidPostBinding().execute(samlRequest, samlResponse, relayState, null);
    }

    @Path("clients/{client_id}")
    @GET
    public Response redirectBinding(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                    @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                    @QueryParam(GeneralConstants.RELAY_STATE) String relayState,
                                    @PathParam("client_id") String clientId)  {
        return new SpidRedirectBinding().execute(samlRequest, samlResponse, relayState, clientId);
    }

    /**
     */
    @Path("clients/{client_id}")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response postBinding(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                @FormParam(GeneralConstants.RELAY_STATE) String relayState,
                                @PathParam("client_id") String clientId) {
        return new SpidPostBinding().execute(samlRequest, samlResponse, relayState, clientId);
    }

    protected abstract class SpidBinding extends SAMLEndpoint.Binding {

        public Response execute(String samlRequest, String samlResponse, String relayState, String clientId) {
            event = new EventBuilder(realm, session, clientConnection);
            return super.execute(samlRequest, samlResponse, relayState, clientId);
        }

        protected Response handleLoginResponse(String samlResponse, SAMLDocumentHolder holder, ResponseType responseType, String relayState, String clientId) {
            try {
                AuthenticationSessionModel authSession;
                if (StringUtil.isNotBlank(clientId)) {
                    authSession = samlIdpInitiatedSSO(clientId);
                } else if (StringUtil.isNotBlank(relayState)) {
                    authSession = callback.getAndVerifyAuthenticationSession(relayState);
                } else {
                    logger.error("SAML RelayState parameter was null when it should be returned by the IDP");
                    event.event(EventType.LOGIN);
                    event.error(Errors.INVALID_SAML_RESPONSE);
                    return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
                session.getContext().setAuthenticationSession(authSession);

                Response response = super.handleLoginResponse(samlResponse, holder, responseType, relayState, clientId);

                if (!isSuccessfulSamlResponse(responseType)) {
                    // Translate SPID error codes to meaningful messages
                    boolean isSpidFault = responseType.getStatus() != null
                        && responseType.getStatus().getStatusMessage() != null
                        && responseType.getStatus().getStatusMessage().startsWith("ErrorCode nr");
                    if (isSpidFault)
                        return callback.error("SpidFault_" + responseType.getStatus().getStatusMessage().replace(' ', '_'));
                    else
                    {
                        String statusMessage = responseType.getStatus() == null || responseType.getStatus().getStatusMessage() == null ? Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR : responseType.getStatus().getStatusMessage();
                        return callback.error(statusMessage);
                    }
                }

                // Apply SPID-specific response validation rules
                boolean assertionIsEncrypted = AssertionUtil.isAssertionEncrypted(responseType);
                Element assertionElement;

                if (assertionIsEncrypted) {
                    try {
                        XMLEncryptionUtil.DecryptionKeyLocator decryptionKeyLocator = new SAMLDecryptionKeysLocator(session, realm, config.getEncryptionAlgorithm());
                        assertionElement = AssertionUtil.decryptAssertion(responseType, decryptionKeyLocator);
                    } catch (ProcessingException ex) {
                        logger.warnf(ex, "Not possible to decrypt SAML assertion. Please check realm keys of usage ENC in the realm '%s' and make sure there is a key able to decrypt the assertion encrypted by identity provider '%s'", realm.getName(), config.getAlias());
                        throw new WebApplicationException(ex, Response.Status.BAD_REQUEST);
                    }
                } else {
                    /* We verify the assertion using original document to handle cases where the IdP
                    includes whitespace and/or newlines inside tags. */
                    assertionElement = DocumentUtil.getElement(holder.getSamlDocument(), new QName(JBossSAMLConstants.ASSERTION.get()));
                }
                String spidExpectedRequestId = authSession.getClientNote(SamlProtocol.SAML_REQUEST_ID_BROKER);
                String requestIssueInstant = authSession.getClientNote(SpidIdentityProvider.SPID_REQUEST_ISSUE_INSTANT);
                String idpEntityId = config.getIdpEntityId();
                String spidResponseValidationError = verifySpidResponse(holder.getSamlDocument().getDocumentElement(), assertionElement, spidExpectedRequestId, requestIssueInstant, idpEntityId);
                if (spidResponseValidationError != null)
                {
                    logger.error("SPID Response Validation Error: " + spidResponseValidationError);
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                    event.error(Errors.INVALID_SAML_RESPONSE);
                    if (config.isDebugEnabled()) {
                        return callback.error(spidResponseValidationError);
                    } else {
                        return callback.error("SpidSamlCheck_GenericError");
                    }
                }
                return response;
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                throw new IdentityBrokerException("Could not process response from SAML identity provider.", e);
            }
        }

         /**
         * If there is a client whose SAML IDP-initiated SSO URL name is set to the
         * given {@code clientUrlName}, creates a fresh authentication session for that
         * client and returns a {@link AuthenticationSessionModel} object with that session.
         * Otherwise returns "client not found" response.
         *
         * @param clientUrlName
         * @return see description
         */
        private AuthenticationSessionModel samlIdpInitiatedSSO(final String clientUrlName) {
            event.event(EventType.LOGIN);
            CacheControlUtil.noBackButtonCacheControlHeader(session);
            Optional<ClientModel> oClient = SpidSAMLEndpoint.this.session.clients()
              .searchClientsByAttributes(realm, Collections.singletonMap(SamlProtocol.SAML_IDP_INITIATED_SSO_URL_NAME, clientUrlName), 0, 1)
              .findFirst();

            if (! oClient.isPresent()) {
                event.error(Errors.CLIENT_NOT_FOUND);
                Response response = ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.CLIENT_NOT_FOUND);
                throw new WebApplicationException(response);
            }

            LoginProtocolFactory factory = (LoginProtocolFactory) session.getKeycloakSessionFactory().getProviderFactory(LoginProtocol.class, SamlProtocol.LOGIN_PROTOCOL);
            SamlService samlService = (SamlService) factory.createProtocolEndpoint(SpidSAMLEndpoint.this.session, event);
            AuthenticationSessionModel authSession = samlService.getOrCreateLoginSessionForIdpInitiatedSso(session, SpidSAMLEndpoint.this.realm, oClient.get(), null);
            if (authSession == null) {
                event.error(Errors.INVALID_REDIRECT_URI);
                Response response = ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REDIRECT_URI);
                throw new WebApplicationException(response);
            }

            return authSession;
        }

        private boolean isSuccessfulSamlResponse(ResponseType responseType) {
            return responseType != null
              && responseType.getStatus() != null
              && responseType.getStatus().getStatusCode() != null
              && responseType.getStatus().getStatusCode().getValue() != null
              && Objects.equals(responseType.getStatus().getStatusCode().getValue().toString(), JBossSAMLURIConstants.STATUS_SUCCESS.get());
        }
    }
    
    /*
     * copy-pasted from SAMLEndpoint.PostBinding since it cannot extend 2 different classes
     */
    protected class SpidPostBinding extends SpidBinding {
        @Override
        protected boolean containsUnencryptedSignature(SAMLDocumentHolder documentHolder) {
            NodeList nl = documentHolder.getSamlDocument().getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            return (nl != null && nl.getLength() > 0);
        }

        @Override
        protected void verifySignature(String key, SAMLDocumentHolder documentHolder) throws VerificationException {
            if ((! containsUnencryptedSignature(documentHolder)) && (documentHolder.getSamlObject() instanceof ResponseType)) {
                ResponseType responseType = (ResponseType) documentHolder.getSamlObject();
                List<ResponseType.RTChoiceType> assertions = responseType.getAssertions();
                if (! assertions.isEmpty() ) {
                    // Only relax verification if the response is an authnresponse and contains (encrypted/plaintext) assertion.
                    // In that case, signature is validated on assertion element
                    return;
                }
            }
            SamlProtocolUtils.verifyDocumentSignature(documentHolder.getSamlDocument(), getIDPKeyLocator());
        }

        @Override
        protected SAMLDocumentHolder extractRequestDocument(String samlRequest) {
            return SAMLRequestParser.parseRequestPostBinding(samlRequest);
        }
        @Override
        protected SAMLDocumentHolder extractResponseDocument(String response) {
            byte[] samlBytes = PostBindingUtil.base64Decode(response);
            return SAMLRequestParser.parseResponseDocument(samlBytes);
        }

        @Override
        protected String getBindingType() {
            return SamlProtocol.SAML_POST_BINDING;
        }
    }

     /*
     * copy-pasted from SAMLEndpoint.RedirectBinding since it cannot extend 2 different classes
     */
    protected class SpidRedirectBinding extends SpidBinding {
        @Override
        protected boolean containsUnencryptedSignature(SAMLDocumentHolder documentHolder) {
            MultivaluedMap<String, String> encodedParams = session.getContext().getUri().getQueryParameters(false);
            String algorithm = encodedParams.getFirst(GeneralConstants.SAML_SIG_ALG_REQUEST_KEY);
            String signature = encodedParams.getFirst(GeneralConstants.SAML_SIGNATURE_REQUEST_KEY);
            return algorithm != null && signature != null;
        }

        @Override
        protected void verifySignature(String key, SAMLDocumentHolder documentHolder) throws VerificationException {
            KeyLocator locator = getIDPKeyLocator();
            SamlProtocolUtils.verifyRedirectSignature(documentHolder, locator, session.getContext().getUri(), key);
        }



        @Override
        protected SAMLDocumentHolder extractRequestDocument(String samlRequest) {
            return SAMLRequestParser.parseRequestRedirectBinding(samlRequest);
        }

        @Override
        protected SAMLDocumentHolder extractResponseDocument(String response) {
            return SAMLRequestParser.parseResponseRedirectBinding(response);
        }

        @Override
        protected String getBindingType() {
            return SamlProtocol.SAML_REDIRECT_BINDING;
        }

    }

    private String verifySpidResponse(Element documentElement, Element assertionElement, String expectedRequestId, String requestIssueInstant, String idpEntityId) {
		// 08: Response > ID empty
        String responseIDToValue = documentElement.getAttribute("ID");
        if (responseIDToValue.isEmpty()) {
            return "SpidSamlCheck_nr08";
        }

		// 03: Response > IssueInstant invalid format.
        String responseIssueInstantToValue = documentElement.getAttribute("IssueInstant");
        if (!responseIssueInstantToValue.isEmpty()) {
			Pattern utcPattern = Pattern.compile(_UTC_STRING);
			if (!utcPattern.matcher(responseIssueInstantToValue).find()) {
				return "SpidSamlCheck_nr13";
			}
        }
        
        try {
        	// 14: IssueInstant attribute prior to IssueInstant of the request (SPID check nr14)
			XMLGregorianCalendar requestIssueInstantTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(requestIssueInstant);
	        XMLGregorianCalendar responseIssueInstantTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(responseIssueInstantToValue);
	        if (responseIssueInstantTime.compare(requestIssueInstantTime) == DatatypeConstants.LESSER) {
	        	return "SpidSamlCheck_nr14";
	        }
	        // 15: IssueInstant attribute following the instant of receipt (SPID check nr15)
	        XMLGregorianCalendar requestFutureIssueInstantTime = (XMLGregorianCalendar)requestIssueInstantTime.clone();
	        requestFutureIssueInstantTime.add(DatatypeFactory.newInstance().newDuration(true, 0, 0, 0, 0, 3, 0));
	        if (responseIssueInstantTime.compare(requestFutureIssueInstantTime) == DatatypeConstants.GREATER) {
	        	return "SpidSamlCheck_nr15";
	        }
        } catch (DatatypeConfigurationException e) {
			logger.error(e);
			return "SpidSamlCheck_nr14";
		}

        Element issuerElement = getDirectChild(documentElement, "Issuer");
               
        // 28: Missing Issuer element (SPID check nr28)
        if (issuerElement == null) {
            return "SpidSamlCheck_nr28";
        }

        // 27: Issuer element is empty (SPID check nr27)
        if (!issuerElement.hasChildNodes() || !org.keycloak.saml.common.util.StringUtil.isNotNull(issuerElement.getFirstChild().getNodeValue()) || hasNamedChild(issuerElement)) {
        	return "SpidSamlCheck_nr27";
        }
        
        // 29: Issuer element different from EntityID IdP (SPID check nr29)
        if (!issuerElement.getFirstChild().getNodeValue().equals(idpEntityId)) {
        	return "SpidSamlCheck_nr29";
        }
        
        // 30: Issuer Format attribute must be omitted or take value urn:oasis:names:tc:SAML:2.0:nameid-format:entity (SPID check nr30)
        if (issuerElement.hasAttribute("Format")) {
        	if (!issuerElement.getAttribute("Format").equals(JBossSAMLURIConstants.NAMEID_FORMAT_ENTITY.get())) {
        		return "SpidSamlCheck_nr30";
        	}
        }

        // 33: Assertion ID attribute is empty (SPID check nr33)
        String responseAssertionIDToValue = assertionElement.getAttribute("ID");
        if (responseAssertionIDToValue.isEmpty()) {
            return "SpidSamlCheck_nr33";
        }

        String responseAssertionIssueInstantToValue = assertionElement.getAttribute("IssueInstant");
        try {
        	// 39: IssueInstant attribute of the Assertion prior to the IssueInstant of the Request (SPID check nr39)
			XMLGregorianCalendar requestIssueInstantTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(requestIssueInstant);
	        XMLGregorianCalendar assertionIssueInstantTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(responseAssertionIssueInstantToValue);
	        if (assertionIssueInstantTime.compare(requestIssueInstantTime) == DatatypeConstants.LESSER) {
	        	return "SpidSamlCheck_nr39";
	        }
	        // 40: IssueInstant attribute of the Assertion following the IssueInstant of the Request (SPID check nr40)
	        XMLGregorianCalendar requestFutureIssueInstantTime = (XMLGregorianCalendar)requestIssueInstantTime.clone();
	        requestFutureIssueInstantTime.add(DatatypeFactory.newInstance().newDuration(true, 0, 0, 0, 0, 3, 0));
	        if (assertionIssueInstantTime.compare(requestFutureIssueInstantTime) == DatatypeConstants.GREATER) {
	        	return "SpidSamlCheck_nr40";
	        }
        } catch (DatatypeConfigurationException e) {
			logger.error(e);
			return "SpidSamlCheck_nr39";
		}
        
        Element subjectElement = getDirectChild(assertionElement, "Subject");
     
        // 42: Assertion > Subject missing
        if (subjectElement == null) {
            return "SpidSamlCheck_nr42";
        }

        // 41: Assertion > Subject element is empty (SPID check nr41)
        if (!hasNamedChild(subjectElement)) {
            return "SpidSamlCheck_nr41";
        }
        
        Element nameIdElement = getDirectChild(subjectElement, "NameID");
        
        // 44: Missing Assertion NameID element (SPID check nr44)
        if (nameIdElement == null) {
            return "SpidSamlCheck_nr44";
        }

        // 43: NameID element of the Assertion is empty (SPID check nr43)
        if (!nameIdElement.hasChildNodes() || !org.keycloak.saml.common.util.StringUtil.isNotNull(nameIdElement.getFirstChild().getNodeValue()) || hasNamedChild(nameIdElement)) {
        	return "SpidSamlCheck_nr43";
        }
                
        if (nameIdElement.hasAttribute("Format")) {
        	// 45: Format attribute of the NameID element of the Assertion is empty (SPID check nr45)
        	if (nameIdElement.getAttribute("Format").isEmpty()) {
        		return "SpidSamlCheck_nr45";
        	}
        	// 47: Assertion NameID Format attribute other than urn:oasis:names:tc:SAML:2.0:nameidformat:transient (SPID check nr47)
        	if (!nameIdElement.getAttribute("Format").equals(JBossSAMLURIConstants.NAMEID_FORMAT_TRANSIENT.get())) {
        		return "SpidSamlCheck_nr47";
        	}
        } else {
        	// 46: Missing Assertion NameID Element Format attribute (SPID check nr46)
        	return "SpidSamlCheck_nr46";
        }
        
        // 49: NameQualifier attribute of NameID of Assertion is missing (SPID check nr49)
        if (!nameIdElement.hasAttribute("NameQualifier")) {
        	return "SpidSamlCheck_nr49";
        }

        // 48: NameQualifier attribute of NameID of the Assertion is empty (SPID check nr48)
        if (nameIdElement.getAttribute("NameQualifier").isEmpty()) {
        	return "SpidSamlCheck_nr48";
        }
        
        // 17: Response > InResponseTo missing
        if (!documentElement.hasAttribute("InResponseTo")) {
            return "SpidSamlCheck_nr17";
        }

        // 16: Response > InResponseTo empty
        String responseInResponseToValue = documentElement.getAttribute("InResponseTo");
        if (responseInResponseToValue.isEmpty()) {
            return "SpidSamlCheck_nr16";
        }

        // 18: Response > InResponseTo does not match request ID
        if (!responseInResponseToValue.equals(expectedRequestId)) {
            return "SpidSamlCheck_nr18";
        }

        // 52: Assertion > Subject > Confirmation missing
        Element subjectConfirmationElement = getDirectChild(subjectElement, "SubjectConfirmation");

        if (subjectConfirmationElement == null) {
            return "SpidSamlCheck_nr52";
        }
        
        // 51: Assertion > Subject > Confirmation empty
        if (!hasNamedChild(subjectConfirmationElement)) {
            return "SpidSamlCheck_nr51";
        }

        // 53: Assertion > Subject > Confirmation > Method missing
        if (!subjectConfirmationElement.hasAttribute("Method")) {
            return "SpidSamlCheck_nr54";
        }

        // 54: Assertion > Subject > Confirmation > Method empty
        String subjectConfirmationMethodValue = subjectConfirmationElement.getAttribute("Method");
        if (subjectConfirmationMethodValue.isEmpty()) {
            return "SpidSamlCheck_nr53";
        }

        // 55: Assertion > Subject > Confirmation > Method is not JBossSAMLURIConstants.SUBJECT_CONFIRMATION_BEARER
        if (!subjectConfirmationMethodValue.equals(JBossSAMLURIConstants.SUBJECT_CONFIRMATION_BEARER.get())) {
            return "SpidSamlCheck_nr55";
        }

        Element subjectConfirmationDataElement = getDirectChild(subjectConfirmationElement, "SubjectConfirmationData"); 

        // 56: Assertion > Subject > Confirmation > SubjectConfirmationData missing
        if (subjectConfirmationDataElement == null) {
            return "SpidSamlCheck_nr56";
        }

        // 58: Assertion > Subject > Confirmation > SubjectConfirmationData > Recipient missing
        if (!subjectConfirmationDataElement.hasAttribute("Recipient")) {
            return "SpidSamlCheck_nr58";
        }
        
        // 57: Assertion > Subject > Confirmation > SubjectConfirmationData > Recipient is empty
        String subjectConfirmationDataRecipientValue = subjectConfirmationDataElement.getAttribute("Recipient");
        if (subjectConfirmationDataRecipientValue.isEmpty()) {
            return "SpidSamlCheck_nr57";
        }

        // 59: 
        if (!subjectConfirmationDataRecipientValue.equals(documentElement.getAttribute("Destination"))) {
        	return "SpidSamlCheck_nr59";
        }
        
        // 61: Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo missing
        if (!subjectConfirmationDataElement.hasAttribute("InResponseTo")) {
            return "SpidSamlCheck_nr61";
        }
        
        // 60: Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo is empty
        String subjectConfirmationDataInResponseToValue = subjectConfirmationDataElement.getAttribute("InResponseTo");
        if (subjectConfirmationDataInResponseToValue.isEmpty()) {
            return "SpidSamlCheck_nr60";
        }

        // 62: Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo does not match request ID
        if (!subjectConfirmationDataInResponseToValue.equals(expectedRequestId)) {
            return "SpidSamlCheck_nr62";
        }

        // 64: NotOnOrAfter attribute of SubjectConfirmationData is missing (SPID check nr64)
        if (!subjectConfirmationDataElement.hasAttribute("NotOnOrAfter")) {
            return "SpidSamlCheck_nr64";
        }
        
        try {
        	// 66: NotOnOrAfter attribute of SubjectConfirmationData prior to the time the response was received (SPID check nr66)
			XMLGregorianCalendar notOnOrAfterTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(subjectConfirmationDataElement.getAttribute("NotOnOrAfter"));
			GregorianCalendar gregorianCalendar = new GregorianCalendar();
	        DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
	        XMLGregorianCalendar now = datatypeFactory.newXMLGregorianCalendar(gregorianCalendar);
			if (notOnOrAfterTime.compare(now) == DatatypeConstants.LESSER) {
	        	return "SpidSamlCheck_nr66";
	        }
        } catch (DatatypeConfigurationException e) {
			logger.error(e);
			return "SpidSamlCheck_nr66";
		}
        
        Element assertionIssuerElement = getDirectChild(assertionElement, "Issuer");
        
        // 68: Missing Issuer element of the Assertion (SPID check nr68)
        if (assertionIssuerElement == null) {
            return "SpidSamlCheck_nr68";
        }

        // 67: Issuer element of the Assertion is empty (SPID check nr67)
        if (!assertionIssuerElement.hasChildNodes() || !org.keycloak.saml.common.util.StringUtil.isNotNull(assertionIssuerElement.getFirstChild().getNodeValue()) || hasNamedChild(assertionIssuerElement)) {
        	return "SpidSamlCheck_nr67";
        }
        
        // 69: Issuer element of the Assertion different from EntityID IdP (SPID check nr69)
        if (!assertionIssuerElement.getFirstChild().getNodeValue().equals(idpEntityId)) {
        	return "SpidSamlCheck_nr69";
        }

        if (assertionIssuerElement.hasAttribute("Format")) {
        	// 70: Format attribute of Issuer of the Assertion is empty (SPID check nr70)
        	if (assertionIssuerElement.getAttribute("Format").isEmpty()) {
        		return "SpidSamlCheck_nr70";
        	}
        	// 72: Format attribute of Issuer of the Assertion must be present with the value urn:oasis:names:tc:SAML:2.0:nameid-format:entity (SPID check nr72)
        	if (!assertionIssuerElement.getAttribute("Format").equals(JBossSAMLURIConstants.NAMEID_FORMAT_ENTITY.get())) {
        		return "SpidSamlCheck_nr72";
        	}
        } else {
        	// 71: Missing Assertion Issuer Format attribute (SPID check nr71)
        	return "SpidSamlCheck_nr71";
        }

        Element conditionsElement = getDirectChild(assertionElement, "Conditions");

        // 74: Missing Assertion Conditions element (SPID check nr74)
        if (conditionsElement == null) {
            return "SpidSamlCheck_nr74";
        }
        
        // 73: Conditions element of the Assertion is empty (SPID check nr73)
        if (!hasNamedChild(conditionsElement)) {
            return "SpidSamlCheck_nr73";
        }

        // 76: Missing Assertion Condition NotBefore attribute (SPID check nr76)
        if (!conditionsElement.hasAttribute("NotBefore")) {
        	return "SpidSamlCheck_nr76";
        }
        
        // 80: Missing Assertion Condition NotOnOrAfter attribute (SPID check nr80)
        if (!conditionsElement.hasAttribute("NotOnOrAfter")) {
        	return "SpidSamlCheck_nr80";
        }

        Element audienceRestrictionElement = getDirectChild(conditionsElement, "AudienceRestriction");

        // 84: Missing Assertion Condition AudienceRestriction element (SPID check nr84)
        if (audienceRestrictionElement == null) {
            return "SpidSamlCheck_nr84";
        }

        Element authnStatementElement = getDirectChild(assertionElement, "AuthnStatement");
        
        // 89: Missing AuthStatement element of the Assertion (SPID check nr89)
        if (authnStatementElement == null) {
        	return "SpidSamlCheck_nr89";
        }
        
        // 88: AuthStatement element of the Assertion is empty (SPID check nr88)
        if (!hasNamedChild(authnStatementElement)) {
            return "SpidSamlCheck_nr88";
        }

        Element authnContextElement = getDirectChild(authnStatementElement, "AuthnContext");

        // 91: Missing AuthStatement AuthnContext Element of Assertion (SPID check nr91)
        if (authnContextElement == null) {
            return "SpidSamlCheck_nr91";
        }

        // 90: AuthnContext of AuthStatement of Assertion is empty (SPID check nr90)
        if (!hasNamedChild(authnContextElement)) {
            return "SpidSamlCheck_nr90";
        }
        
        Element authnContextClassRef = getDirectChild(authnContextElement, "AuthnContextClassRef");
        
        // 93: AuthStatement AuthStatement AuthContextClassRef Element of the Missing Assertion (SPID check nr93)
        if (authnContextClassRef == null) {
            return "SpidSamlCheck_nr93";
        }

        // 92: AuthStatement AuthStatement AuthContextClassRef Element of the Assertion is empty (SPID check nr92)
        if (!authnContextClassRef.hasChildNodes() || !org.keycloak.saml.common.util.StringUtil.isNotNull(authnContextClassRef.getFirstChild().getNodeValue()) || hasNamedChild(authnContextClassRef)) {
        	return "SpidSamlCheck_nr92";
        }
        
        // 97: AuthContextClassRef element set to an unexpected value (SPID check nr97)
        String responseSpidLevel = authnContextClassRef.getFirstChild().getNodeValue();
        int spidLevelResponse = Arrays.asList(SPID_LEVEL).indexOf(responseSpidLevel) + 1;
        
        List<String> spidLevelRequestList = null;
        try {
        	spidLevelRequestList = Arrays.asList(JsonSerialization.readValue(config.getAuthnContextClassRefs(), String[].class));
        } catch (Exception e) {
        	logger.error("Could not json-deserialize AuthContextClassRefs config entry: " + config.getAuthnContextClassRefs(), e);
        	return "SpidSamlCheck_nr97";
        }
        int spidLevelRequest = Arrays.asList(SPID_LEVEL).indexOf(spidLevelRequestList.get(0)) + 1;
        
        if (spidLevelResponse < 1) {
        	return "SpidSamlCheck_nr97";
        }
        
        // 94: AuthContextClassRef element set on https://www.spid.gov.it/SpidL1 (SPID check nr94)
        // 95: AuthContextClassRef element set on https://www.spid.gov.it/SpidL2 (SPID check nr95)
        // 96: AuthContextClassRef element set on https://www.spid.gov.it/SpidL3 (SPID check nr96)
        if (config.getAuthnContextComparisonType().equals(AuthnContextComparisonType.EXACT)) {
        	if (spidLevelResponse != spidLevelRequest) {
        		return getSpidLevelAssertion(spidLevelResponse);
        	}
        } else if (config.getAuthnContextComparisonType().equals(AuthnContextComparisonType.MINIMUM)) {
        	if (spidLevelResponse < spidLevelRequest) {
        		return getSpidLevelAssertion(spidLevelResponse);
        	}
        } else if (config.getAuthnContextComparisonType().equals(AuthnContextComparisonType.MAXIMUM)) {
        	if (spidLevelResponse > spidLevelRequest) {
        		return getSpidLevelAssertion(spidLevelResponse);
        	}
        } else if (config.getAuthnContextComparisonType().equals(AuthnContextComparisonType.BETTER)) {
        	if (!responseSpidLevel.equals(config.getAuthnContextClassRefs())) {
        		return getSpidLevelAssertion(spidLevelResponse);
        	}
        }
        
        return null;
    }

    private String getSpidLevelAssertion(int spidLevel) {
    	switch (spidLevel) {
	    	case 1 : {
	    		return "SpidSamlCheck_nr94";
	    	}
	    	case 2 : {
	    		return "SpidSamlCheck_nr95";
	    	}
	    	case 3 : {
	    		return "SpidSamlCheck_nr96";
	    	}
	    	default : {
	    		return "SpidSamlCheck_nr97";
	    	}
    	}
    }
    
    private boolean hasNamedChild(Element element)
    {
        NodeList childNodes = element.getChildNodes();
        if (childNodes == null) return false;

        for (int i = 0; i < childNodes.getLength(); ++i)
        {
            Node node = childNodes.item(i);
            if (node.getNodeType() ==  Node.ELEMENT_NODE && node.getNodeName() != null)
                return true;
        }

        return false;
    }
    
    private Element getDirectChild(Element parent, String name)
    {
        for(Node child = parent.getFirstChild(); child != null; child = child.getNextSibling())
        {
            if(child instanceof Element && name.equals(child.getLocalName())) return (Element) child;
        }
        return null;
    }
    
}
