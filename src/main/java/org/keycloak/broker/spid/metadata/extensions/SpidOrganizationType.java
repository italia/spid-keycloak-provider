package org.keycloak.broker.spid.metadata.extensions;

import org.jboss.logging.Logger;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.dom.saml.v2.metadata.LocalizedNameType;
import org.keycloak.dom.saml.v2.metadata.LocalizedURIType;
import org.keycloak.dom.saml.v2.metadata.OrganizationType;
import org.keycloak.saml.common.util.StringUtil;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

public class SpidOrganizationType extends OrganizationType {

    protected static final Logger logger = Logger.getLogger(SpidOrganizationType.class);

    public static Optional<OrganizationType> build(final SpidIdentityProviderConfig config) {
        if ( StringUtil.isNullOrEmpty(config.getOrganizationNames()) &&
             StringUtil.isNullOrEmpty(config.getOrganizationDisplayNames()) &&
            StringUtil.isNullOrEmpty(config.getOrganizationUrls()) ) {
            return Optional.empty();
        } else {
            return Optional.of(new SpidOrganizationType(config));
        }
    }

    private SpidOrganizationType(final SpidIdentityProviderConfig config) {
        if (config.getOrganizationNames() != null) {
            for (String organizationNameStr : config.getOrganizationNames().split(",")) {
                String[] parsedName = organizationNameStr.split("\\|", 2);
                if (parsedName.length < 2) {
                    continue;
                }
                LocalizedNameType organizationName = new LocalizedNameType(parsedName[0].trim());
                organizationName.setValue(parsedName[1].trim());
                this.addOrganizationName(organizationName);
            }
        }

        if (config.getOrganizationDisplayNames() != null) {
            for (String organizationDisplayNameStr : config.getOrganizationDisplayNames().split(",")) {
                String[] parsedDisplayName = organizationDisplayNameStr.split("\\|", 2);
                if (parsedDisplayName.length < 2) {
                    continue;
                }

                LocalizedNameType organizationDisplayName = new LocalizedNameType(parsedDisplayName[0].trim());
                organizationDisplayName.setValue(parsedDisplayName[1].trim());
                this.addOrganizationDisplayName(organizationDisplayName);
            }
        }

        if (config.getOrganizationUrls() != null) {
            for (String organizationUrlStr : config.getOrganizationUrls().split(",")) {
                String[] parsedUrl = organizationUrlStr.split("\\|", 2);
                if (parsedUrl.length < 2) {
                    continue;
                }

                LocalizedURIType organizationUrl = new LocalizedURIType(parsedUrl[0].trim());
                try {
                    organizationUrl.setValue(new URI(parsedUrl[1].trim()));
                } catch (URISyntaxException e) {
                    logger.error("Error creating URI for Organization URL");
                    continue;
                }
                this.addOrganizationURL(organizationUrl);
            }
        }
    }
}
