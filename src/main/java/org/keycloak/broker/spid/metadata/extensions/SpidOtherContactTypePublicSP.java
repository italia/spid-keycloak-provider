package org.keycloak.broker.spid.metadata.extensions;

import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.saml.common.exceptions.ConfigurationException;

class SpidOtherContactTypePublicSP extends SpidOtherContactType {

    public SpidOtherContactTypePublicSP(final SpidIdentityProviderConfig config) throws ConfigurationException {
        super(config);

        // IPA Code
        addExtensionElement("spid:IPACode", config.getIpaCode());

        addQualifier("spid:Public");
    }
}
