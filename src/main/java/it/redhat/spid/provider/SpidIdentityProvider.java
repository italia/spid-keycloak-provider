package it.redhat.spid.provider;

import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;

import javax.ws.rs.core.Response;

public class SpidIdentityProvider extends AbstractIdentityProvider<SpidIdentityProviderConfig> {

    public SpidIdentityProvider(KeycloakSession session, SpidIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Response retrieveToken(KeycloakSession keycloakSession, FederatedIdentityModel identityModel) {
        return Response.ok(identityModel.getToken()).build();
    }

}
