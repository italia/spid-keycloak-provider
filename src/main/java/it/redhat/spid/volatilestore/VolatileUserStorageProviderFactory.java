package it.redhat.spid.volatilestore;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;

public class VolatileUserStorageProviderFactory implements UserStorageProviderFactory<VolatileUserStorageProvider> {

    private static final Logger logger = Logger.getLogger(VolatileUserStorageProviderFactory.class);

    public static final String PROVIDER_NAME = "volatile-user-store";

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public VolatileUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        return new VolatileUserStorageProvider(session, model);
    }
}
