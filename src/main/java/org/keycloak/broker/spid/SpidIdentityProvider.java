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

import org.jboss.logging.Logger;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.validators.DestinationValidator;

/**
 * @author Pedro Igor
 */
public class SpidIdentityProvider extends SAMLIdentityProvider {
    protected static final Logger logger = Logger.getLogger(SpidIdentityProvider.class);

    public static final String SPID_REQUEST_ISSUE_INSTANT = "SPID_REQUEST_ISSUE_INSTANT";

    private final DestinationValidator destinationValidator;

    public SpidIdentityProvider(KeycloakSession session, SpidIdentityProviderConfig config, DestinationValidator destinationValidator) {
        super(session, config, destinationValidator);
        this.destinationValidator = destinationValidator;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new SpidSAMLEndpoint(session, this, getConfig(), callback, destinationValidator);
    }

    public SpidIdentityProviderConfig getConfig() {
        return new SpidIdentityProviderConfig(super.getConfig());
    }

}