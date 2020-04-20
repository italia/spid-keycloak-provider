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

import org.keycloak.dom.saml.v2.protocol.NameIDPolicyType;

import java.net.URI;

/**
 * @author pedroigor
 */
public class SpidSAML2NameIDPolicyBuilder {
    private final NameIDPolicyType policyType;
    private Boolean allowCreate;
    private String spNameQualifier;

    private SpidSAML2NameIDPolicyBuilder(String format) {
        this.policyType = new NameIDPolicyType();
        this.policyType.setFormat(URI.create(format));
    }

    public static SpidSAML2NameIDPolicyBuilder format(String format) {
        return new SpidSAML2NameIDPolicyBuilder(format);
    }

    public SpidSAML2NameIDPolicyBuilder setAllowCreate(Boolean allowCreate) {
        this.allowCreate = allowCreate;
        return this;
    }

    public SpidSAML2NameIDPolicyBuilder setSPNameQualifier(String spNameQualifier) {
        this.spNameQualifier = spNameQualifier;
        return this;
    }

    public NameIDPolicyType build() {
        if (this.allowCreate != null)
            this.policyType.setAllowCreate(this.allowCreate);

        if (spNameQualifier != null)
            this.policyType.setSPNameQualifier(this.spNameQualifier);

        return this.policyType;
    }
}