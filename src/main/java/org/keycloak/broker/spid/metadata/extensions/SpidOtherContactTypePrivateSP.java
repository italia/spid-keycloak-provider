package org.keycloak.broker.spid.metadata.extensions;

import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.saml.common.exceptions.ConfigurationException;

class SpidOtherContactTypePrivateSP extends SpidOtherContactType {

    public SpidOtherContactTypePrivateSP(final SpidIdentityProviderConfig config) throws ConfigurationException {
        super(config);

        // VAT Number
        addExtensionElement("spid:VATNumber", config.getVatNumber());
        // Fiscal Code
        addExtensionElement("spid:FiscalCode", config.getFiscalCode());

        addQualifier("spid:Private");
    }
}
