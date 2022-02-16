package org.keycloak.broker.spid.metadata.extensions;

import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.dom.saml.v2.metadata.ContactType;
import org.keycloak.dom.saml.v2.metadata.ContactTypeType;
import org.keycloak.dom.saml.v2.metadata.ExtensionsType;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.w3c.dom.Element;

import java.util.Optional;

public abstract class SpidOtherContactType extends ContactType {

    public static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";
    public static final String SPID_METADATA_EXTENSIONS_NS = "https://spid.gov.it/saml-extensions";

    public static Optional<SpidOtherContactType> build(final SpidIdentityProviderConfig config) throws ConfigurationException {
        if ( StringUtil.isNullOrEmpty(config.getOtherContactCompany()) &&
            StringUtil.isNullOrEmpty(config.getOtherContactEmail()) &&
            StringUtil.isNullOrEmpty(config.getOtherContactPhone())) {
            return Optional.empty();
        } else {
            return Optional.of(config.isSpPrivate() ? new SpidOtherContactTypePrivateSP(config) : new SpidOtherContactTypePublicSP(config));
        }
    }

    protected SpidOtherContactType(final SpidIdentityProviderConfig config) {
        super(ContactTypeType.OTHER);
        if (!StringUtil.isNullOrEmpty(config.getOtherContactCompany())) {
            this.setCompany(config.getOtherContactCompany());
        }
        if (!StringUtil.isNullOrEmpty(config.getOtherContactEmail())) {
            this.addEmailAddress(config.getOtherContactEmail());
        }
        if (!StringUtil.isNullOrEmpty(config.getOtherContactPhone())) {
            this.addTelephone(config.getOtherContactPhone());
        }
        this.setExtensions(new ExtensionsType());
    }

    protected void addQualifier(String qualifier) throws ConfigurationException {
        // Private qualifier
        Element spTypeElement = DocumentUtil.createDocument().createElementNS(SPID_METADATA_EXTENSIONS_NS, qualifier );
        spTypeElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
        getExtensions().addExtension(spTypeElement);
    }

    protected void addExtensionElement(String name, String value) throws ConfigurationException {
        if (!StringUtil.isNullOrEmpty(value))
        {
            Element ipaCodeElement = DocumentUtil.createDocument().createElementNS(SPID_METADATA_EXTENSIONS_NS, name);
            ipaCodeElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
            ipaCodeElement.setTextContent(value);
            getExtensions().addExtension(ipaCodeElement);
        }
    }

}
