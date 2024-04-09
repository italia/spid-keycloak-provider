package org.keycloak.broker.spid;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.dom.saml.v2.protocol.RequestAbstractType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.SAML2NameIDBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.sessions.AuthenticationSessionModel;

public class SpidSamlAuthenticationPreprocessor implements SamlAuthenticationPreprocessor {

    private KeycloakSession session;
    private static Boolean allowCreate = Boolean.TRUE; // @TODO pass over
    protected static final Logger logger = Logger.getLogger(SpidSamlAuthenticationPreprocessor.class);

    @Override
    public String getId() {
        return SpidSamlAuthenticationPreprocessor.class.getName();
    }

    @Override
    public AuthnRequestType beforeSendingLoginRequest(AuthnRequestType authnRequest, AuthenticationSessionModel authSession) {
        spidIssuer(authnRequest);
        spidNameIDPolicy(authnRequest);
        authSession.setClientNote(SpidIdentityProvider.SPID_REQUEST_ISSUE_INSTANT, authnRequest.getIssueInstant().toXMLFormat());
        return authnRequest;
    }

    @Override
    public LogoutRequestType beforeSendingLogoutRequest(LogoutRequestType logoutRequest, UserSessionModel authSession, AuthenticatedClientSessionModel clientSession) {
        spidIssuer(logoutRequest);
        return logoutRequest;
    }

    private static void spidIssuer(RequestAbstractType authnRequest) {
        String issuerURL = authnRequest.getIssuer().getValue();
        logger.info("SPID customization: issuer (original " + issuerURL + ")");
        authnRequest.setIssuer(SAML2NameIDBuilder.value(issuerURL)
                .setNameQualifier(issuerURL) // SPID: attributo NameQualifier in Issuer
                .setFormat(JBossSAMLURIConstants.NAMEID_FORMAT_ENTITY.get()) // SPID: attributo Format in Issuer
                .build());
    }

    private static void spidNameIDPolicy(AuthnRequestType authnRequest) {
        String nameIDPolicyFormat = authnRequest.getNameIDPolicy().getFormat().toString();
        String issuerURL = authnRequest.getIssuer().getValue();
        logger.debug("SPID customization: nameIDPolicyFormat (original " + nameIDPolicyFormat + ")");
        authnRequest.setNameIDPolicy(SAML2NameIDPolicyBuilder
                .format(nameIDPolicyFormat)
                .setSPNameQualifier(issuerURL) // SPID: attributo SPNameQualifier in NameIDPolicy
                .setAllowCreate(allowCreate).build());
    }

    @Override
    public SamlAuthenticationPreprocessor create(KeycloakSession session) {
        this.session = session;
        return this;
    }

    @Override
    public void close() {
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

}