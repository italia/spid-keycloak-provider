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
package it.redhat.spid.saml;

import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.RequestedAuthnContextType;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.SamlProtocolExtensionsAwareBuilder;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import org.keycloak.saml.processing.core.saml.v2.common.IDGenerator;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.w3c.dom.Document;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import org.keycloak.dom.saml.v2.protocol.ExtensionsType;

/**
 * @author pedroigor
 */
public class SpidSAML2AuthnRequestBuilder implements SamlProtocolExtensionsAwareBuilder<SpidSAML2AuthnRequestBuilder> {

    private final AuthnRequestType authnRequestType;
    protected String destination;
    protected String issuer;
    protected final List<NodeGenerator> extensions = new LinkedList<>();

    public SpidSAML2AuthnRequestBuilder destination(String destination) {
        this.destination = destination;
        return this;
    }

    public SpidSAML2AuthnRequestBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    @Override
    public SpidSAML2AuthnRequestBuilder addExtension(NodeGenerator extension) {
        this.extensions.add(extension);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder() {
        this.authnRequestType = new AuthnRequestType(IDGenerator.create("ID_"), XMLTimeUtil.getIssueInstant());
    }

    public SpidSAML2AuthnRequestBuilder assertionConsumerUrl(String assertionConsumerUrl) {
        this.authnRequestType.setAssertionConsumerServiceURL(URI.create(assertionConsumerUrl));
        return this;
    }

    public SpidSAML2AuthnRequestBuilder assertionConsumerUrl(URI assertionConsumerUrl) {
        this.authnRequestType.setAssertionConsumerServiceURL(assertionConsumerUrl);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder forceAuthn(boolean forceAuthn) {
        this.authnRequestType.setForceAuthn(forceAuthn);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder isPassive(boolean isPassive) {
        this.authnRequestType.setIsPassive(isPassive);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder requestedAuthnContext(String requestedAuthnContext, AuthnContextComparisonType authnContextComparisonType) {
        this.authnRequestType.setRequestedAuthnContext(new RequestedAuthnContextType());
        this.authnRequestType.getRequestedAuthnContext().addAuthnContextClassRef(requestedAuthnContext);
        this.authnRequestType.getRequestedAuthnContext().setComparison(authnContextComparisonType);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder nameIdPolicy(SAML2NameIDPolicyBuilder nameIDPolicyBuilder) {
        this.authnRequestType.setNameIDPolicy(nameIDPolicyBuilder.build());
        return this;
    }

    public SpidSAML2AuthnRequestBuilder protocolBinding(String protocolBinding) {
        this.authnRequestType.setProtocolBinding(URI.create(protocolBinding));
        return this;
    }

    public Document toDocument() {
        try {
            AuthnRequestType authnRequestType = createAuthnRequest();

            return new SpidSAML2Request().convert(authnRequestType);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Could not convert " + authnRequestType + " to a document.", e);
        }
    }

    public AuthnRequestType createAuthnRequest() {
        AuthnRequestType res = this.authnRequestType;
        NameIDType nameIDType = new NameIDType();
        nameIDType.setValue(this.issuer);

        // SPID: Aggiungi l'attributo NameQualifier all'elemento Issuer
        nameIDType.setNameQualifier(this.issuer);

        // SPID: Aggiungi l'attributo Format all'elemento Issuer
        nameIDType.setFormat(JBossSAMLURIConstants.NAMEID_FORMAT_ENTITY.getUri());

        // SPID: Aggiungi l'attributo AttributeConsumingServiceIndex
        res.setAttributeConsumingServiceIndex(1);

        res.setIssuer(nameIDType);

        res.setDestination(URI.create(this.destination));

        if (!this.extensions.isEmpty()) {
            ExtensionsType extensionsType = new ExtensionsType();
            for (NodeGenerator extension : this.extensions) {
                extensionsType.addExtension(extension);
            }
            res.setExtensions(extensionsType);
        }

        return res;
    }
}