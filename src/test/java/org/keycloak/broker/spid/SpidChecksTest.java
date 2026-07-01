package org.keycloak.broker.spid;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SpidChecksTest {

    private SpidChecks spidChecks;

    @BeforeEach
    void setUp() {
        spidChecks = new SpidChecks(new SpidIdentityProviderConfig());
    }

    @Test
    void validateGrantedAttributeAuthority_shouldPassWhenExtensionsIsMissing() throws Exception {
        assertNull(spidChecks.validateGrantedAttributeAuthority(parseResponseElement("")));
    }

    @Test
    void validateGrantedAttributeAuthority_shouldFailWhenGrantTokenIsMissing() throws Exception {
        String extensionsXml = "<samlp:Extensions>"
            + "<spid:GrantedAttributeAuthority xmlns:spid=\"https://spid.gov.it/saml-extensions\"/>"
            + "</samlp:Extensions>";

        assertEquals(
            "SpidSamlCheck_MissingGrantToken",
            spidChecks.validateGrantedAttributeAuthority(parseResponseElement(extensionsXml))
        );
    }

    @Test
    void validateGrantedAttributeAuthority_shouldFailWhenGrantTokenDestinationIsMissing() throws Exception {
        String extensionsXml = "<samlp:Extensions>"
            + "<spid:GrantedAttributeAuthority xmlns:spid=\"https://spid.gov.it/saml-extensions\">"
            + "<spid:GrantToken>token</spid:GrantToken>"
            + "</spid:GrantedAttributeAuthority>"
            + "</samlp:Extensions>";

        assertEquals(
            "SpidSamlCheck_MissingGrantTokenDestination",
            spidChecks.validateGrantedAttributeAuthority(parseResponseElement(extensionsXml))
        );
    }

    @Test
    void validateGrantedAttributeAuthority_shouldFailWhenGrantTokenDestinationIsEmpty() throws Exception {
        String extensionsXml = "<samlp:Extensions>"
            + "<spid:GrantedAttributeAuthority xmlns:spid=\"https://spid.gov.it/saml-extensions\">"
            + "<spid:GrantToken Destination=\"  \">token</spid:GrantToken>"
            + "</spid:GrantedAttributeAuthority>"
            + "</samlp:Extensions>";

        assertEquals(
            "SpidSamlCheck_EmptyGrantTokenDestination",
            spidChecks.validateGrantedAttributeAuthority(parseResponseElement(extensionsXml))
        );
    }

    @Test
    void validateGrantedAttributeAuthority_shouldPassWhenGrantTokenDestinationIsValid() throws Exception {
        String extensionsXml = "<samlp:Extensions>"
            + "<spid:GrantedAttributeAuthority xmlns:spid=\"https://spid.gov.it/saml-extensions\">"
            + "<spid:GrantToken Destination=\"https://sp.example.it/auth/realms/test/broker/spid/endpoint\">token</spid:GrantToken>"
            + "</spid:GrantedAttributeAuthority>"
            + "</samlp:Extensions>";

        assertNull(spidChecks.validateGrantedAttributeAuthority(parseResponseElement(extensionsXml)));
    }

    private Element parseResponseElement(String responseChildrenXml) throws Exception {
        String responseXml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
            + responseChildrenXml
            + "</samlp:Response>";

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder()
            .parse(new InputSource(new StringReader(responseXml)))
            .getDocumentElement();
    }
}
