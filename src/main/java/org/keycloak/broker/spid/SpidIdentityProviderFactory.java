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

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import org.keycloak.Config.Scope;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.broker.spid.metadata.SpidSpMetadataResourceProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.saml.validators.DestinationValidator;

/**
 * @author Pedro Igor
 */
public class SpidIdentityProviderFactory extends AbstractIdentityProviderFactory<SpidIdentityProvider> {

    public static final String PROVIDER_ID = "spid-saml";

    private DestinationValidator destinationValidator;
    private SAMLIdentityProviderFactory samlIdentityProviderFactory;
    
    @Override
    public String getName() {
        return "SPID";
    }

    @Override
    public SpidIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        model.getConfig().put(SpidIdentityProviderConfig.METADATA_URL, SpidSpMetadataResourceProvider.getMetadataURL(session).toString());
        samlIdentityProviderFactory = new SAMLIdentityProviderFactory();
        return new SpidIdentityProvider(session, new SpidIdentityProviderConfig(model), destinationValidator);
    }

    @Override
    public SpidIdentityProviderConfig createConfig() {
        return new SpidIdentityProviderConfig();
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, InputStream inputStream) {
        return samlIdentityProviderFactory.parseConfig(session, inputStream);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Scope config) {
        super.init(config);

        this.destinationValidator = DestinationValidator.forProtocolMap(config.getArray("knownProtocols"));
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return SpidIdentityProviderConfig.getConfigProperties();
    }
}
