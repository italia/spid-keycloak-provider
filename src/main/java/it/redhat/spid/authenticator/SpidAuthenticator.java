package it.redhat.spid.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class SpidAuthenticator extends AbstractIdpAuthenticator {
    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        UserModel existingUser =
                context.getSession().users().getUserByUsername(
                        brokerContext.getModelUsername(),
                        context.getRealm()
                );

        if (existingUser != null) {
            context.setUser(existingUser);
            context.success();
        } else {
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
        }
    }

}

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext
            serializedCtx, BrokeredIdentityContext brokerContext) {
        authenticateImpl(context, serializedCtx, brokerContext);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

}
