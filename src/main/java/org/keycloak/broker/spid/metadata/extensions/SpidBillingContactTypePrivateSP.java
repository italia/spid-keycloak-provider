package org.keycloak.broker.spid.metadata.extensions;

import org.jboss.logging.Logger;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.util.StringUtil;
import org.w3c.dom.Element;

import java.util.Optional;

public class SpidBillingContactTypePrivateSP extends SpidBillingContactType {
    protected static final Logger logger = Logger.getLogger(SpidBillingContactTypePrivateSP.class);
    public static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";
    public static final String SPID_METADATA_INVOICING_EXTENSIONS_NS = "https://spid.gov.it/invoicing-extensions";

    public SpidBillingContactTypePrivateSP(final SpidIdentityProviderConfig config) throws ConfigurationException {
        super(config);

        final Element customerTransferee = createElement("fpa:CessionarioCommittente");
        customerTransferee.appendChild(createPersonalData(config));
        customerTransferee.appendChild(createHeadQuarters(config));
        extensions.addExtension(customerTransferee);
    }

    protected Element createPersonalData(final SpidIdentityProviderConfig config) {
        final Element personalData = createElement("fpa:DatiAnagrafici");

        final Element vatFiscalCode = createElement("fpa:IdFiscaleIVA");
        if (StringUtil.isNullOrEmpty(config.getVatNumber()) || config.getVatNumber().length() < 13) {
            logger.errorf("Invalid VAT number % ", config.getVatNumber());
        } else {
            createElement("fpa:IdPaese", config.getVatNumber().substring(0, 2)).ifPresent(vatFiscalCode::appendChild);
            createElement("fpa:IdCodice", config.getVatNumber().substring(3, 13)).ifPresent(vatFiscalCode::appendChild);
        }
        personalData.appendChild(vatFiscalCode);

        final Element registry = createElement("fpa:Anagrafica");
        createElement("fpa:Denominazione", config.getBillingContactRegistryName()).ifPresent(registry::appendChild);
        personalData.appendChild(registry);

        return personalData;
    }

    protected Element createHeadQuarters(final SpidIdentityProviderConfig config) {
        Element headQuarters = createElement("fpa:Sede");
        createElement("fpa:Indirizzo", config.getBillingContactSiteAddress()).ifPresent(headQuarters::appendChild);
        createElement("fpa:NumeroCivico", config.getBillingContactSiteNumber()).ifPresent(headQuarters::appendChild);
        createElement("fpa:CAP", config.getBillingContactSiteZipCode()).ifPresent(headQuarters::appendChild);
        createElement("fpa:Comune", config.getBillingContactSiteCity()).ifPresent(headQuarters::appendChild);
        createElement("fpa:Provincia", config.getBillingContactSiteProvince()).ifPresent(headQuarters::appendChild);
        createElement("fpa:Nazione", config.getBillingContactSiteCountry()).ifPresent(headQuarters::appendChild);
        return headQuarters;
    }

    protected Element createElement(String name) {
        Element element = doc.createElementNS(SPID_METADATA_INVOICING_EXTENSIONS_NS, name);
        element.setAttributeNS(XMLNS_NS, "xmlns:fpa", SPID_METADATA_INVOICING_EXTENSIONS_NS);
        return element;
    }

    protected Optional<Element> createElement(String name, String value) {
        if (StringUtil.isNullOrEmpty(value)) {
            return Optional.empty();
        }
        Element element = doc.createElementNS(SPID_METADATA_INVOICING_EXTENSIONS_NS, name);
        element.setAttributeNS(XMLNS_NS, "xmlns:fpa", SPID_METADATA_INVOICING_EXTENSIONS_NS);
        element.setTextContent(value);
        return Optional.of(element);
    }

}
