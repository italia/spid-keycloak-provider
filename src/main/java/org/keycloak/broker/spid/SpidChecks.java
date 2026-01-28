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
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Arrays;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.regex.Pattern;

/**
 * SPID-specific response validation checks.
 * Contains validation logic for SPID SAML responses according to SPID technical rules.
 */
public class SpidChecks {
    private static final Logger logger = Logger.getLogger(SpidChecks.class);

    // ISO 8601 fully compliant regex for date/time validation
    private static final String _UTC_STRING = "^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$";

    // SPID authentication levels
    private static final String[] SPID_LEVEL = {
        "https://www.spid.gov.it/SpidL1",
        "https://www.spid.gov.it/SpidL2",
        "https://www.spid.gov.it/SpidL3"
    };

    private final SpidIdentityProviderConfig config;

    public SpidChecks(SpidIdentityProviderConfig config) {
        this.config = config;
    }

    /**
     * Orchestrates SPID response validation by extracting parameters from the session
     * and validating the SAML response and assertion.
     * Returns null if validation passes, or an error code string if validation fails.
     *
     * @param authSession the authentication session containing request metadata
     * @param holder the SAML document holder
     * @param assertionElement the assertion element (decrypted if necessary)
     * @return null if valid, error code string if validation fails
     */
    public String validateSpidResponse(AuthenticationSessionModel authSession,
                                       SAMLDocumentHolder holder,
                                       Element assertionElement) {
        // Extract parameters from authentication session
        String expectedRequestId = authSession.getClientNote(SamlProtocol.SAML_REQUEST_ID_BROKER);
        String requestIssueInstant = authSession.getClientNote(SpidIdentityProvider.SPID_REQUEST_ISSUE_INSTANT);
        String idpEntityId = config.getIdpEntityId();

        // Perform comprehensive SPID validation
        return verifySpidResponse(
            holder.getSamlDocument().getDocumentElement(),
            assertionElement,
            expectedRequestId,
            requestIssueInstant,
            idpEntityId
        );
    }

    /**
     * Performs comprehensive SPID response validation according to SPID technical rules.
     * Returns null if validation passes, or an error code string if validation fails.
     */
    public String verifySpidResponse(Element documentElement, Element assertionElement,
                                     String expectedRequestId, String requestIssueInstant, String idpEntityId) {
        // 08: Response > ID empty
        String responseIDToValue = documentElement.getAttribute("ID");
        if (responseIDToValue.isEmpty()) {
            return "SpidSamlCheck_nr08";
        }

        // 13: Response > IssueInstant invalid format
        String responseIssueInstantToValue = documentElement.getAttribute("IssueInstant");
        if (!responseIssueInstantToValue.isEmpty()) {
            Pattern utcPattern = Pattern.compile(_UTC_STRING);
            if (!utcPattern.matcher(responseIssueInstantToValue).find()) {
                return "SpidSamlCheck_nr13";
            }
        }

        try {
            // 14: IssueInstant attribute prior to IssueInstant of the request
            XMLGregorianCalendar requestIssueInstantTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(requestIssueInstant);
            XMLGregorianCalendar responseIssueInstantTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(responseIssueInstantToValue);
            if (responseIssueInstantTime.compare(requestIssueInstantTime) == DatatypeConstants.LESSER) {
                return "SpidSamlCheck_nr14";
            }
            // 15: IssueInstant attribute following the instant of receipt
            XMLGregorianCalendar requestFutureIssueInstantTime = (XMLGregorianCalendar) requestIssueInstantTime.clone();
            requestFutureIssueInstantTime.add(DatatypeFactory.newInstance().newDuration(true, 0, 0, 0, 0, 3, 0));
            if (responseIssueInstantTime.compare(requestFutureIssueInstantTime) == DatatypeConstants.GREATER) {
                return "SpidSamlCheck_nr15";
            }
        } catch (DatatypeConfigurationException e) {
            logger.error(e);
            return "SpidSamlCheck_nr14";
        }

        Element issuerElement = getDirectChild(documentElement, "Issuer");

        // 28: Missing Issuer element
        if (issuerElement == null) {
            return "SpidSamlCheck_nr28";
        }

        // 27: Issuer element is empty
        if (!issuerElement.hasChildNodes() ||
            !org.keycloak.saml.common.util.StringUtil.isNotNull(issuerElement.getFirstChild().getNodeValue()) ||
            hasNamedChild(issuerElement)) {
            return "SpidSamlCheck_nr27";
        }

        // 29: Issuer element different from EntityID IdP
        if (!issuerElement.getFirstChild().getNodeValue().equals(idpEntityId)) {
            return "SpidSamlCheck_nr29";
        }

        // 30: Issuer Format attribute must be omitted or take value urn:oasis:names:tc:SAML:2.0:nameid-format:entity
        if (issuerElement.hasAttribute("Format")) {
            if (!issuerElement.getAttribute("Format").equals(JBossSAMLURIConstants.NAMEID_FORMAT_ENTITY.get())) {
                return "SpidSamlCheck_nr30";
            }
        }

        // 33: Assertion ID attribute is empty
        String responseAssertionIDToValue = assertionElement.getAttribute("ID");
        if (responseAssertionIDToValue.isEmpty()) {
            return "SpidSamlCheck_nr33";
        }

        String responseAssertionIssueInstantToValue = assertionElement.getAttribute("IssueInstant");
        try {
            // 39: IssueInstant attribute of the Assertion prior to the IssueInstant of the Request
            XMLGregorianCalendar requestIssueInstantTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(requestIssueInstant);
            XMLGregorianCalendar assertionIssueInstantTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(responseAssertionIssueInstantToValue);
            if (assertionIssueInstantTime.compare(requestIssueInstantTime) == DatatypeConstants.LESSER) {
                return "SpidSamlCheck_nr39";
            }
            // 40: IssueInstant attribute of the Assertion following the IssueInstant of the Request
            XMLGregorianCalendar requestFutureIssueInstantTime = (XMLGregorianCalendar) requestIssueInstantTime.clone();
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

        // 41: Assertion > Subject element is empty
        if (!hasNamedChild(subjectElement)) {
            return "SpidSamlCheck_nr41";
        }

        Element nameIdElement = getDirectChild(subjectElement, "NameID");

        // 44: Missing Assertion NameID element
        if (nameIdElement == null) {
            return "SpidSamlCheck_nr44";
        }

        // 43: NameID element of the Assertion is empty
        if (!nameIdElement.hasChildNodes() ||
            !org.keycloak.saml.common.util.StringUtil.isNotNull(nameIdElement.getFirstChild().getNodeValue()) ||
            hasNamedChild(nameIdElement)) {
            return "SpidSamlCheck_nr43";
        }

        if (nameIdElement.hasAttribute("Format")) {
            // 45: Format attribute of the NameID element of the Assertion is empty
            if (nameIdElement.getAttribute("Format").isEmpty()) {
                return "SpidSamlCheck_nr45";
            }
            // 47: Assertion NameID Format attribute other than urn:oasis:names:tc:SAML:2.0:nameid-format:transient
            if (!nameIdElement.getAttribute("Format").equals(JBossSAMLURIConstants.NAMEID_FORMAT_TRANSIENT.get())) {
                return "SpidSamlCheck_nr47";
            }
        } else {
            // 46: Missing Assertion NameID Element Format attribute
            return "SpidSamlCheck_nr46";
        }

        // 49: NameQualifier attribute of NameID of Assertion is missing
        if (!nameIdElement.hasAttribute("NameQualifier")) {
            return "SpidSamlCheck_nr49";
        }

        // 48: NameQualifier attribute of NameID of the Assertion is empty
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

        // 54: Assertion > Subject > Confirmation > Method missing
        if (!subjectConfirmationElement.hasAttribute("Method")) {
            return "SpidSamlCheck_nr54";
        }

        // 53: Assertion > Subject > Confirmation > Method empty
        String subjectConfirmationMethodValue = subjectConfirmationElement.getAttribute("Method");
        if (subjectConfirmationMethodValue.isEmpty()) {
            return "SpidSamlCheck_nr53";
        }

        // 55: Assertion > Subject > Confirmation > Method is not SUBJECT_CONFIRMATION_BEARER
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

        // 59: Recipient does not match Destination
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

        // 64: NotOnOrAfter attribute of SubjectConfirmationData is missing
        if (!subjectConfirmationDataElement.hasAttribute("NotOnOrAfter")) {
            return "SpidSamlCheck_nr64";
        }

        try {
            // 66: NotOnOrAfter attribute of SubjectConfirmationData prior to the time the response was received
            XMLGregorianCalendar notOnOrAfterTime = DatatypeFactory.newInstance()
                .newXMLGregorianCalendar(subjectConfirmationDataElement.getAttribute("NotOnOrAfter"));
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

        // 68: Missing Issuer element of the Assertion
        if (assertionIssuerElement == null) {
            return "SpidSamlCheck_nr68";
        }

        // 67: Issuer element of the Assertion is empty
        if (!assertionIssuerElement.hasChildNodes() ||
            !org.keycloak.saml.common.util.StringUtil.isNotNull(assertionIssuerElement.getFirstChild().getNodeValue()) ||
            hasNamedChild(assertionIssuerElement)) {
            return "SpidSamlCheck_nr67";
        }

        // 69: Issuer element of the Assertion different from EntityID IdP
        if (!assertionIssuerElement.getFirstChild().getNodeValue().equals(idpEntityId)) {
            return "SpidSamlCheck_nr69";
        }

        if (assertionIssuerElement.hasAttribute("Format")) {
            // 70: Format attribute of Issuer of the Assertion is empty
            if (assertionIssuerElement.getAttribute("Format").isEmpty()) {
                return "SpidSamlCheck_nr70";
            }
            // 72: Format attribute of Issuer of the Assertion must be urn:oasis:names:tc:SAML:2.0:nameid-format:entity
            if (!assertionIssuerElement.getAttribute("Format").equals(JBossSAMLURIConstants.NAMEID_FORMAT_ENTITY.get())) {
                return "SpidSamlCheck_nr72";
            }
        } else {
            // 71: Missing Assertion Issuer Format attribute
            return "SpidSamlCheck_nr71";
        }

        Element conditionsElement = getDirectChild(assertionElement, "Conditions");

        // 74: Missing Assertion Conditions element
        if (conditionsElement == null) {
            return "SpidSamlCheck_nr74";
        }

        // 73: Conditions element of the Assertion is empty
        if (!hasNamedChild(conditionsElement)) {
            return "SpidSamlCheck_nr73";
        }

        // 76: Missing Assertion Condition NotBefore attribute
        if (!conditionsElement.hasAttribute("NotBefore")) {
            return "SpidSamlCheck_nr76";
        }

        // 80: Missing Assertion Condition NotOnOrAfter attribute
        if (!conditionsElement.hasAttribute("NotOnOrAfter")) {
            return "SpidSamlCheck_nr80";
        }

        Element audienceRestrictionElement = getDirectChild(conditionsElement, "AudienceRestriction");

        // 84: Missing Assertion Condition AudienceRestriction element
        if (audienceRestrictionElement == null) {
            return "SpidSamlCheck_nr84";
        }

        Element authnStatementElement = getDirectChild(assertionElement, "AuthnStatement");

        // 89: Missing AuthStatement element of the Assertion
        if (authnStatementElement == null) {
            return "SpidSamlCheck_nr89";
        }

        // 88: AuthStatement element of the Assertion is empty
        if (!hasNamedChild(authnStatementElement)) {
            return "SpidSamlCheck_nr88";
        }

        Element authnContextElement = getDirectChild(authnStatementElement, "AuthnContext");

        // 91: Missing AuthStatement AuthnContext Element of Assertion
        if (authnContextElement == null) {
            return "SpidSamlCheck_nr91";
        }

        // 90: AuthnContext of AuthStatement of Assertion is empty
        if (!hasNamedChild(authnContextElement)) {
            return "SpidSamlCheck_nr90";
        }

        Element authnContextClassRef = getDirectChild(authnContextElement, "AuthnContextClassRef");

        // 93: AuthStatement AuthContextClassRef Element of the Missing Assertion
        if (authnContextClassRef == null) {
            return "SpidSamlCheck_nr93";
        }

        // 92: AuthStatement AuthContextClassRef Element of the Assertion is empty
        if (!authnContextClassRef.hasChildNodes() ||
            !org.keycloak.saml.common.util.StringUtil.isNotNull(authnContextClassRef.getFirstChild().getNodeValue()) ||
            hasNamedChild(authnContextClassRef)) {
            return "SpidSamlCheck_nr92";
        }

        // 97: AuthContextClassRef element set to an unexpected value
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

        // 94-96: AuthContextClassRef element set to wrong SPID level
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

    /**
     * Checks if a SAML response contains a SPID fault error code.
     * SPID faults are indicated by status messages starting with "ErrorCode nr".
     *
     * @param responseType the SAML response to check
     * @return true if the response contains a SPID fault, false otherwise
     */
    public boolean isSpidFault(StatusResponseType responseType) {
        return responseType.getStatus() != null
            && responseType.getStatus().getStatusMessage() != null
            && responseType.getStatus().getStatusMessage().startsWith("ErrorCode nr");
    }

    /**
     * Formats a SPID fault status message for error page display.
     * Converts "ErrorCode nr XX" to "SpidFault_ErrorCode_nr_XX" format.
     *
     * @param statusMessage the raw status message from the SPID response
     * @return formatted error message suitable for error page display
     */
    public String formatSpidFaultMessage(String statusMessage) {
        return "SpidFault_" + statusMessage.replace(' ', '_');
    }

    private String getSpidLevelAssertion(int spidLevel) {
        switch (spidLevel) {
            case 1:
                return "SpidSamlCheck_nr94";
            case 2:
                return "SpidSamlCheck_nr95";
            case 3:
                return "SpidSamlCheck_nr96";
            default:
                return "SpidSamlCheck_nr97";
        }
    }

    private boolean hasNamedChild(Element element) {
        NodeList childNodes = element.getChildNodes();
        if (childNodes == null) return false;

        for (int i = 0; i < childNodes.getLength(); ++i) {
            Node node = childNodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName() != null) {
                return true;
            }
        }
        return false;
    }

    private Element getDirectChild(Element parent, String name) {
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element && name.equals(child.getLocalName())) {
                return (Element) child;
            }
        }
        return null;
    }
}
