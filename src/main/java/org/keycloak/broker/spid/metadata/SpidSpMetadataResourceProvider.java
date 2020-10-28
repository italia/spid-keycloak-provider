/*
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

package org.keycloak.broker.spid.metadata;

import org.jboss.logging.Logger;

import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.keycloak.dom.saml.v2.metadata.EndpointType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.IndexedEndpointType;
import org.keycloak.dom.saml.v2.metadata.KeyDescriptorType;
import org.keycloak.dom.saml.v2.metadata.KeyTypes;
import org.keycloak.dom.saml.v2.metadata.LocalizedNameType;
import org.keycloak.dom.saml.v2.metadata.LocalizedURIType;
import org.keycloak.dom.saml.v2.metadata.OrganizationType;
import org.keycloak.dom.saml.v2.metadata.RequestedAttributeType;
import org.keycloak.dom.saml.v2.metadata.SPSSODescriptorType;
import org.keycloak.keys.RsaKeyMetadata;
import org.keycloak.models.KeyManager;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.SPMetadataDescriptor;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.processing.core.saml.v2.common.IDGenerator;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;
import org.keycloak.saml.processing.api.saml.v2.sig.SAML2Signature;
import org.keycloak.services.resource.RealmResourceProvider;

import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.keycloak.broker.spid.SpidIdentityProvider;
import org.keycloak.broker.spid.SpidIdentityProviderFactory;
import org.keycloak.broker.spid.mappers.SpidUserAttributeMapper;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC;
import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.PROTOCOL_NSURI;

public class SpidSpMetadataResourceProvider implements RealmResourceProvider {
    protected static final Logger logger = Logger.getLogger(SpidSpMetadataResourceProvider.class);

    private KeycloakSession session;

    public SpidSpMetadataResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Produces("text/xml; charset=utf-8")
    public Response get() {
        try
        {
            RealmModel realm = session.getContext().getRealm();
            List<IdentityProviderModel> lstIdentityProviders = realm.getIdentityProviders();
            List<IdentityProviderModel> lstSpidIdentityProviders = lstIdentityProviders.stream()
                .filter(t -> t.getProviderId().equals(SpidIdentityProviderFactory.PROVIDER_ID) &&
                    t.isEnabled())
                .sorted((o1,o2)-> o1.getAlias().compareTo(o2.getAlias()))
                .collect(Collectors.toList());

            if (lstSpidIdentityProviders.size() == 0)
                throw new Exception("No SPID providers found!");

            SpidIdentityProviderFactory providerFactory = new SpidIdentityProviderFactory();
            SpidIdentityProvider firstSpidProvider = providerFactory.create(session, lstSpidIdentityProviders.get(0));

            UriInfo uriInfo = session.getContext().getUri();

            URI authnBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.getUri();

            if (firstSpidProvider.getConfig().isPostBindingAuthnRequest()) {
                authnBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.getUri();
            }

            List<URI> assertionEndpoints = lstSpidIdentityProviders.stream()
                    .map(t -> uriInfo.getBaseUriBuilder()
                        .path("realms").path(realm.getName())
                        .path("broker")
                        .path(t.getAlias())
                        .path("endpoint")
                    .build()).collect(Collectors.toList());

            List<URI> logoutEndpoints = lstSpidIdentityProviders.stream()
                .map(t -> uriInfo.getBaseUriBuilder()
                    .path("realms").path(realm.getName())
                    .path("broker")
                    .path(t.getAlias())
                    .path("endpoint")
                    .build()).collect(Collectors.toList());

            boolean wantAuthnRequestsSigned = firstSpidProvider.getConfig().isWantAuthnRequestsSigned();
            boolean wantAssertionsSigned = firstSpidProvider.getConfig().isWantAssertionsSigned();
            boolean wantAssertionsEncrypted = firstSpidProvider.getConfig().isWantAssertionsEncrypted();
            String configEntityId = firstSpidProvider.getConfig().getEntityId();
            String entityId = getEntityId(configEntityId, uriInfo, realm);
            String nameIDPolicyFormat = firstSpidProvider.getConfig().getNameIDPolicyFormat();

            List<Element> signingKeys = new ArrayList<Element>();
            List<Element> encryptionKeys = new ArrayList<Element>();

            Set<RsaKeyMetadata> keys = new TreeSet<>((o1, o2) -> o1.getStatus() == o2.getStatus() // Status can be only PASSIVE OR ACTIVE, push PASSIVE to end of list
              ? (int) (o2.getProviderPriority() - o1.getProviderPriority())
              : (o1.getStatus() == KeyStatus.PASSIVE ? 1 : -1));
            keys.addAll(session.keys().getRsaKeys(realm));
            for (RsaKeyMetadata key : keys) {
                if (key == null || key.getCertificate() == null) continue;

                signingKeys.add(SPMetadataDescriptor.buildKeyInfoElement(key.getKid(), PemUtils.encodeCertificate(key.getCertificate())));

                if (key.getStatus() == KeyStatus.ACTIVE)
                    encryptionKeys.add(SPMetadataDescriptor.buildKeyInfoElement(key.getKid(), PemUtils.encodeCertificate(key.getCertificate())));
            }

            Integer attributeConsumingServiceIndex = firstSpidProvider.getConfig().getAttributeConsumingServiceIndex();
            Set<IdentityProviderMapperModel> lstFirstProviderMappers = realm.getIdentityProviderMappersByAlias(firstSpidProvider.getConfig().getAlias());
            List<String> requestedAttributeNames = lstFirstProviderMappers.stream().filter(t -> t.getIdentityProviderMapper().equals(SpidUserAttributeMapper.PROVIDER_ID))
                .map(t -> t.getConfig().get(SpidUserAttributeMapper.ATTRIBUTE_NAME))
                .collect(Collectors.toList());

            String strAttributeConsumingServiceNames = firstSpidProvider.getConfig().getAttributeConsumingServiceNames();
            String[] attributeConsumingServiceNames = strAttributeConsumingServiceNames != null ? strAttributeConsumingServiceNames.split(","): null;

            String strOrganizationNames = firstSpidProvider.getConfig().getOrganizationNames();
            String[] organizationNames = strOrganizationNames != null ? strOrganizationNames.split(","): null;

            String strOrganizationDisplayNames = firstSpidProvider.getConfig().getOrganizationDisplayNames();
            String[] organizationDisplayNames = strOrganizationDisplayNames != null ? strOrganizationDisplayNames.split(","): null;

            String strOrganizationUrls = firstSpidProvider.getConfig().getOrganizationUrls();
            String[] organizationUrls = strOrganizationUrls != null ? strOrganizationUrls.split(","): null;

            String descriptor = getSPDescriptor(authnBinding, assertionEndpoints, logoutEndpoints,
              wantAuthnRequestsSigned, wantAssertionsSigned, wantAssertionsEncrypted,
              entityId, nameIDPolicyFormat, signingKeys, encryptionKeys,
              attributeConsumingServiceIndex, attributeConsumingServiceNames, requestedAttributeNames,
              organizationNames, organizationDisplayNames, organizationUrls);

            if (firstSpidProvider.getConfig().isSignSpMetadata()) {
                KeyManager.ActiveRsaKey activeKey = session.keys().getActiveRsaKey(realm);
                String keyName = firstSpidProvider.getConfig().getXmlSigKeyInfoKeyNameTransformer().getKeyName(activeKey.getKid(), activeKey.getCertificate());
                KeyPair keyPair = new KeyPair(activeKey.getPublicKey(), activeKey.getPrivateKey());

                Document metadataDocument = DocumentUtil.getDocument(descriptor);
                SAML2Signature signatureHelper = new SAML2Signature();
                signatureHelper.setSignatureMethod(firstSpidProvider.getSignatureAlgorithm().getXmlSignatureMethod());
                signatureHelper.setDigestMethod(firstSpidProvider.getSignatureAlgorithm().getXmlSignatureDigestMethod());

                Node nextSibling = metadataDocument.getDocumentElement().getFirstChild();
                signatureHelper.setNextSibling(nextSibling);

                signatureHelper.signSAMLDocument(metadataDocument, keyName, keyPair, CanonicalizationMethod.EXCLUSIVE);

                descriptor = DocumentUtil.getDocumentAsString(metadataDocument);
            }

            return Response.ok(descriptor, MediaType.APPLICATION_XML_TYPE).build();
        } catch (Exception e) {
            logger.warn("Failed to export SAML SP Metadata!", e);
            throw new RuntimeException(e);
        }
    }

    private String getEntityId(String configEntityId, UriInfo uriInfo, RealmModel realm) {
        if (configEntityId == null || configEntityId.isEmpty())
            return UriBuilder.fromUri(uriInfo.getBaseUri()).path("realms").path(realm.getName()).build().toString();
        else
            return configEntityId;
    }

    private static String getSPDescriptor(URI binding, List<URI> assertionEndpoints, List<URI> logoutEndpoints,
        boolean wantAuthnRequestsSigned, boolean wantAssertionsSigned, boolean wantAssertionsEncrypted,
        String entityId, String nameIDPolicyFormat, List<Element> signingCerts, List<Element> encryptionCerts,
        Integer attributeConsumingServiceIndex, String[] attributeConsumingServiceNames, List<String> requestedAttributeNames,
        String[] organizationNames, String[] organizationDisplayNames, String[] organizationUrls) 
        throws XMLStreamException, ProcessingException, ParserConfigurationException
    {
        StringWriter sw = new StringWriter();
        XMLStreamWriter writer = StaxUtil.getXMLStreamWriter(sw);
        SAMLMetadataWriter metadataWriter = new SAMLMetadataWriter(writer);

        EntityDescriptorType entityDescriptor = new EntityDescriptorType(entityId);
        entityDescriptor.setID(IDGenerator.create("ID_"));

        SPSSODescriptorType spSSODescriptor = new SPSSODescriptorType(Arrays.asList(PROTOCOL_NSURI.get()));
        spSSODescriptor.setAuthnRequestsSigned(wantAuthnRequestsSigned);
        spSSODescriptor.setWantAssertionsSigned(wantAssertionsSigned);
        spSSODescriptor.addNameIDFormat(nameIDPolicyFormat);

        if (wantAuthnRequestsSigned && signingCerts != null) {
            for (Element key: signingCerts)
            {
                KeyDescriptorType keyDescriptor = new KeyDescriptorType();
                keyDescriptor.setUse(KeyTypes.SIGNING);
                keyDescriptor.setKeyInfo(key);
                spSSODescriptor.addKeyDescriptor(keyDescriptor);
            }
        }

        if (wantAssertionsEncrypted && encryptionCerts != null) {
            for (Element key: encryptionCerts)
            {
                KeyDescriptorType keyDescriptor = new KeyDescriptorType();
                keyDescriptor.setUse(KeyTypes.ENCRYPTION);
                keyDescriptor.setKeyInfo(key);
                spSSODescriptor.addKeyDescriptor(keyDescriptor);
            }
        }

        // SingleLogoutService
        for (URI logoutEndpoint: logoutEndpoints)
            spSSODescriptor.addSingleLogoutService(new EndpointType(binding, logoutEndpoint));

        // AssertionConsumerService
        int assertionEndpointIndex = 0;
        for (URI assertionEndpoint: assertionEndpoints)
        {
            IndexedEndpointType assertionConsumerEndpoint = new IndexedEndpointType(binding, assertionEndpoint);
            if (assertionEndpointIndex == 0) assertionConsumerEndpoint.setIsDefault(true);
            assertionConsumerEndpoint.setIndex(assertionEndpointIndex);

            spSSODescriptor.addAssertionConsumerService(assertionConsumerEndpoint);
            assertionEndpointIndex++;
        }

        // AttributeConsumingService
        AttributeConsumingServiceType attributeConsumingService = new AttributeConsumingServiceType(attributeConsumingServiceIndex);
        attributeConsumingService.setIsDefault(null);

        if (attributeConsumingServiceNames != null && attributeConsumingServiceNames.length > 0)
        {
            for (String attributeConsumingServiceNameStr: attributeConsumingServiceNames)
            {
                String[] parsedName = attributeConsumingServiceNameStr.split("\\|", 2);
                if (parsedName.length < 2) continue;

                LocalizedNameType attributeConsumingServiceName = new LocalizedNameType(parsedName[0]);
                attributeConsumingServiceName.setValue(parsedName[1]);
                attributeConsumingService.addServiceName(attributeConsumingServiceName);
            }
        }

        for (String requestedAttributeName: requestedAttributeNames) {
            RequestedAttributeType requestedAttribute = new RequestedAttributeType(requestedAttributeName);
            requestedAttribute.setNameFormat(ATTRIBUTE_FORMAT_BASIC.get());

            attributeConsumingService.addRequestedAttribute(requestedAttribute);
        }

        spSSODescriptor.addAttributeConsumerService(attributeConsumingService);

        entityDescriptor.addChoiceType(new EntityDescriptorType.EDTChoiceType(Arrays.asList(new EntityDescriptorType.EDTDescriptorChoiceType(spSSODescriptor))));

        // Organization
        if (organizationNames != null && organizationNames.length > 0 ||
            organizationDisplayNames != null && organizationDisplayNames.length > 0 ||
            organizationUrls != null && organizationUrls.length > 0)
        {
            OrganizationType organizationType = new OrganizationType();

            if (organizationNames != null) {
                for (String organizationNameStr: organizationNames)
                {
                    String[] parsedName = organizationNameStr.split("\\|", 2);
                    if (parsedName.length < 2) continue;

                    LocalizedNameType organizationName = new LocalizedNameType(parsedName[0].trim());
                    organizationName.setValue(parsedName[1].trim());
                    organizationType.addOrganizationName(organizationName);
                }
            }

            if (organizationDisplayNames != null) {
                for (String organizationDisplayNameStr: organizationDisplayNames)
                {
                    String[] parsedDisplayName = organizationDisplayNameStr.split("\\|", 2);
                    if (parsedDisplayName.length < 2) continue;

                    LocalizedNameType organizationDisplayName = new LocalizedNameType(parsedDisplayName[0].trim());
                    organizationDisplayName.setValue(parsedDisplayName[1].trim());
                    organizationType.addOrganizationDisplayName(organizationDisplayName);
                }
            }

            if (organizationUrls != null) {
                for (String organizationUrlStr: organizationUrls)
                {
                    String[] parsedUrl = organizationUrlStr.split("\\|", 2);
                    if (parsedUrl.length < 2) continue;

                    LocalizedURIType organizationUrl = new LocalizedURIType(parsedUrl[0].trim());
                    try {
                        organizationUrl.setValue(new URI(parsedUrl[1].trim()));
                    } catch (URISyntaxException e) { logger.error("Error creating URI for Organization URL"); continue; };
                    organizationType.addOrganizationURL(organizationUrl);
                }
            }

            entityDescriptor.setOrganization(organizationType);
        }

        metadataWriter.writeEntityDescriptor(entityDescriptor);

        return sw.toString();
    }

    @Override
    public void close() {
    }

}
