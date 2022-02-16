package org.keycloak.broker.spid.metadata.extensions;

import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.dom.saml.v2.metadata.ContactType;
import org.keycloak.dom.saml.v2.metadata.ContactTypeType;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.util.StringUtil;

import java.util.Optional;

public class SpidBillingContactType extends ContactType {

    public static Optional<SpidBillingContactType> build(final SpidIdentityProviderConfig config) throws ConfigurationException {
        if ( StringUtil.isNullOrEmpty(config.getBillingContactCompany()) &&
            StringUtil.isNullOrEmpty(config.getBillingContactEmail()) &&
            StringUtil.isNullOrEmpty(config.getBillingContactPhone())) {
            return Optional.empty();
        } else {
            return Optional.of(new SpidBillingContactType(config));
        }
    }

    private SpidBillingContactType(final SpidIdentityProviderConfig config) {
        super(ContactTypeType.BILLING);

        if (!StringUtil.isNullOrEmpty(config.getBillingContactCompany())) {
            this.setCompany(config.getBillingContactCompany());
        }
        if (!StringUtil.isNullOrEmpty(config.getBillingContactEmail())) {
            this.addEmailAddress(config.getBillingContactEmail());
        }
        if (!StringUtil.isNullOrEmpty(config.getBillingContactPhone())) {
            this.addTelephone(config.getBillingContactPhone());
        }
    }
}
