package it.redhat.spid.provider;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class SpidIdentityProviderFactory extends AbstractIdentityProviderFactory<SpidIdentityProvider> {
    public static final String PROVIDER_ID = "spid";

    @Override
    public String getName() {
        return "SPID";
    }

    @Override
    public SpidIdentityProvider create(KeycloakSession keycloakSession, IdentityProviderModel identityProviderModel) {
        return new SpidIdentityProvider(keycloakSession, new SpidIdentityProviderConfig(identityProviderModel));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
