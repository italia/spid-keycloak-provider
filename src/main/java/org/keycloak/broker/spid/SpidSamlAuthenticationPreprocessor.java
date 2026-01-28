/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.broker.spid;

import org.keycloak.Config;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.SAML2NameIDBuilder;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * SPID-specific SAML authentication preprocessor that modifies AuthnRequest and LogoutRequest
 * to comply with SPID requirements:
 * - Adds NameQualifier and Format attributes to Issuer elements
 * - Adds SPNameQualifier to NameIDPolicy
 * - Stores request IssueInstant for response validation
 */
public class SpidSamlAuthenticationPreprocessor implements SamlAuthenticationPreprocessor {

    public static final String PROVIDER_ID = "spid-saml-preprocessor";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public SamlAuthenticationPreprocessor create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
        // No initialization needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No resources to close
    }

    @Override
    public AuthnRequestType beforeSendingLoginRequest(AuthnRequestType authnRequest,
                                                       AuthenticationSessionModel authSession) {
        // Get the issuer URL from the authnRequest
        String issuerURL = authnRequest.getIssuer().getValue();

        // SPID: Modify Issuer element - add NameQualifier and Format attributes
        NameIDType issuer = SAML2NameIDBuilder.value(issuerURL)
            .setNameQualifier(issuerURL)
            .setFormat(JBossSAMLURIConstants.NAMEID_FORMAT_ENTITY.get())
            .build();
        authnRequest.setIssuer(issuer);

        // SPID: Modify NameIDPolicy - add SPNameQualifier attribute
        if (authnRequest.getNameIDPolicy() != null) {
            authnRequest.getNameIDPolicy().setSPNameQualifier(issuerURL);
        }

        // Store the request IssueInstant in the auth session for SPID response validation
        if (authnRequest.getIssueInstant() != null) {
            authSession.setClientNote(SpidIdentityProvider.SPID_REQUEST_ISSUE_INSTANT,
                                      authnRequest.getIssueInstant().toXMLFormat());
        }

        return authnRequest;
    }

    @Override
    public LogoutRequestType beforeSendingLogoutRequest(LogoutRequestType logoutRequest,
                                                        UserSessionModel userSession,
                                                        AuthenticatedClientSessionModel clientSession) {
        // Get the entity ID from the logoutRequest issuer
        String entityId = logoutRequest.getIssuer().getValue();

        // SPID: Modify Issuer element - add NameQualifier and Format attributes
        NameIDType issuer = SAML2NameIDBuilder.value(entityId)
            .setNameQualifier(entityId)
            .setFormat(JBossSAMLURIConstants.NAMEID_FORMAT_ENTITY.get())
            .build();
        logoutRequest.setIssuer(issuer);

        return logoutRequest;
    }
}
