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

import org.apache.commons.codec.digest.DigestUtils;
import org.jboss.logging.Logger;

import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.broker.spid.metadata.extensions.SpidBillingContactType;
import org.keycloak.broker.spid.metadata.extensions.SpidOrganizationType;
import org.keycloak.broker.spid.metadata.extensions.SpidOtherContactType;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.keycloak.dom.saml.v2.metadata.EndpointType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.IndexedEndpointType;
import org.keycloak.dom.saml.v2.metadata.LocalizedNameType;
import org.keycloak.dom.saml.v2.metadata.SPSSODescriptorType;
import org.keycloak.models.KeyManager;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.SPMetadataDescriptor;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;
import org.keycloak.saml.processing.api.saml.v2.sig.SAML2Signature;
import org.keycloak.protocol.saml.SamlService;
import org.keycloak.protocol.saml.mappers.SamlMetadataDescriptorUpdater;
import org.keycloak.services.resource.RealmResourceProvider;

import java.io.StringWriter;
import java.net.URI;
import java.security.KeyPair;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamWriter;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.spid.SpidIdentityProvider;
import org.keycloak.broker.spid.SpidIdentityProviderFactory;

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
            // Retrieve all enabled SPID Identity Providers for this realms
            RealmModel realm = session.getContext().getRealm();
            List<IdentityProviderModel> lstSpidIdentityProviders = realm.getIdentityProvidersStream()
                .filter(t -> t.getProviderId().equals(SpidIdentityProviderFactory.PROVIDER_ID) &&
                    t.isEnabled())
                .sorted((o1,o2)-> o1.getAlias().compareTo(o2.getAlias()))
                .collect(Collectors.toList());

            if (lstSpidIdentityProviders.size() == 0)
                throw new Exception("No SPID providers found!");

            // Create an instance of the first SPID Identity Provider in alphabetical order
            SpidIdentityProviderFactory providerFactory = new SpidIdentityProviderFactory();
            SpidIdentityProvider firstSpidProvider = providerFactory.create(session, lstSpidIdentityProviders.get(0));

            // Retrieve the context URI
            UriInfo uriInfo = session.getContext().getUri();

            //
            URI authnBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.getUri();

            if (firstSpidProvider.getConfig().isPostBindingAuthnRequest()) {
                authnBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.getUri();
            }

            URI endpoint = uriInfo.getBaseUriBuilder()
                    .path("realms").path(realm.getName())
                    .path("broker")
                    .path(firstSpidProvider.getConfig().getAlias())
                    .path("endpoint")
                    .build();

            boolean wantAuthnRequestsSigned = firstSpidProvider.getConfig().isWantAuthnRequestsSigned();
            boolean wantAssertionsSigned = firstSpidProvider.getConfig().isWantAssertionsSigned();
            boolean wantAssertionsEncrypted = firstSpidProvider.getConfig().isWantAssertionsEncrypted();
            String configEntityId = firstSpidProvider.getConfig().getEntityId();
            String entityId = getEntityId(configEntityId, uriInfo, realm);
            String nameIDPolicyFormat = firstSpidProvider.getConfig().getNameIDPolicyFormat();
            int attributeConsumingServiceIndex = firstSpidProvider.getConfig().getAttributeConsumingServiceIndex() != null ? firstSpidProvider.getConfig().getAttributeConsumingServiceIndex(): 1;
            String attributeConsumingServiceName = firstSpidProvider.getConfig().getAttributeConsumingServiceName();
            String[] attributeConsumingServiceNames = attributeConsumingServiceName != null ? attributeConsumingServiceName.split(","): null;

            List<Element> signingKeys = new LinkedList<>();
            List<Element> encryptionKeys = new LinkedList<>();

            session.keys().getKeysStream(realm, KeyUse.SIG, Algorithm.RS256)
                    .filter(Objects::nonNull)
                    .filter(key -> key.getCertificate() != null)
                    .sorted(SamlService::compareKeys)
                    .forEach(key -> {
                        try {
                            Element element = SPMetadataDescriptor
                                    .buildKeyInfoElement(key.getKid(), PemUtils.encodeCertificate(key.getCertificate()));
                            signingKeys.add(element);

                            if (key.getStatus() == KeyStatus.ACTIVE) {
                                encryptionKeys.add(element);
                            }
                        } catch (ParserConfigurationException e) {
                            logger.warn("Failed to export SAML SP Metadata!", e);
                            throw new RuntimeException(e);
                        }
                    });

            EntityDescriptorType entityDescriptor = SPMetadataDescriptor.buildSPdescriptor(
                authnBinding, authnBinding, endpoint, endpoint,
                wantAuthnRequestsSigned, wantAssertionsSigned, wantAssertionsEncrypted,
                entityId, nameIDPolicyFormat, signingKeys, encryptionKeys);

            // Create the AttributeConsumingService
            AttributeConsumingServiceType attributeConsumingService = new AttributeConsumingServiceType(attributeConsumingServiceIndex);
            attributeConsumingService.setIsDefault(true);

            if (attributeConsumingServiceNames != null && attributeConsumingServiceNames.length > 0)
            {
                for (String attributeConsumingServiceNameStr: attributeConsumingServiceNames)
                {
                    String currentLocale = realm.getDefaultLocale() == null ? "en": realm.getDefaultLocale();

                    String[] parsedName = attributeConsumingServiceNameStr.split("\\|", 2);
                    String serviceNameLocale = parsedName.length >= 2 ? parsedName[0]: currentLocale;

                    LocalizedNameType attributeConsumingServiceNameElement = new LocalizedNameType(serviceNameLocale);
                    attributeConsumingServiceNameElement.setValue(parsedName.length >= 2 ? parsedName[1]: attributeConsumingServiceNameStr);
                    attributeConsumingService.addServiceName(attributeConsumingServiceNameElement);
                }
            }
    
            // Look for the SP descriptor and add the attribute consuming service
            for (EntityDescriptorType.EDTChoiceType choiceType: entityDescriptor.getChoiceType()) {
                List<EntityDescriptorType.EDTDescriptorChoiceType> descriptors = choiceType.getDescriptors();

                if (descriptors != null) {
                    for (EntityDescriptorType.EDTDescriptorChoiceType descriptor: descriptors) {
                        if (descriptor.getSpDescriptor() != null) {
                            descriptor.getSpDescriptor().addAttributeConsumerService(attributeConsumingService);
                        }
                    }
                }
            }
            
            // Add the attribute mappers
            realm.getIdentityProviderMappersByAliasStream(firstSpidProvider.getConfig().getAlias())
                .forEach(mapper -> {
                    IdentityProviderMapper target = (IdentityProviderMapper) session.getKeycloakSessionFactory().getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
                    if (target instanceof SamlMetadataDescriptorUpdater)
                    {
                        SamlMetadataDescriptorUpdater metadataAttrProvider = (SamlMetadataDescriptorUpdater)target;
                        metadataAttrProvider.updateMetadata(mapper, entityDescriptor);
                    }
                });
				

			// Additional EntityDescriptor customizations
            customizeEntityDescriptor(entityDescriptor, firstSpidProvider.getConfig());

            // Additional SPSSODescriptor customizations
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

            for (EntityDescriptorType.EDTChoiceType choiceType: entityDescriptor.getChoiceType()) {
                List<EntityDescriptorType.EDTDescriptorChoiceType> descriptors = choiceType.getDescriptors();
    
                if (descriptors != null) {
                    for (EntityDescriptorType.EDTDescriptorChoiceType descriptor: descriptors) {
                        SPSSODescriptorType spDescriptor = descriptor.getSpDescriptor();
                        
                        if (spDescriptor != null) {
                            customizeSpDescriptor(spDescriptor,
                                authnBinding, authnBinding,
                                assertionEndpoints, logoutEndpoints);
                        }
                    }
                }
            }

            String descriptor = writeEntityDescriptorWithConsistentID(entityDescriptor);

            // Metadata signing
            if (firstSpidProvider.getConfig().isSignSpMetadata())
            {
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

    private String writeEntityDescriptorWithConsistentID(final EntityDescriptorType entityDescriptor) throws ProcessingException {
        // Update ID with hash of content so multiple metadata request give back same xml if configuration is same.
        entityDescriptor.setID("ID_"); // Set to fixed value before hashing
        String data = entityDescriptorAsString(entityDescriptor);
        String hash = DigestUtils.md5Hex(data) ;
        entityDescriptor.setID("ID_" + hash); // Update to hashed value ID
        return entityDescriptorAsString(entityDescriptor);
    }

    private String entityDescriptorAsString(final EntityDescriptorType entityDescriptor) throws ProcessingException {
        StringWriter sw = new StringWriter();
        XMLStreamWriter writer = StaxUtil.getXMLStreamWriter(sw);
        SAMLMetadataWriter metadataWriter = new SAMLMetadataWriter(writer);
        metadataWriter.writeEntityDescriptor(entityDescriptor);
        return sw.toString();
    }

    private String getEntityId(String configEntityId, UriInfo uriInfo, RealmModel realm) {
        if (configEntityId == null || configEntityId.isEmpty())
            return UriBuilder.fromUri(uriInfo.getBaseUri()).path("realms").path(realm.getName()).build().toString();
        else
            return configEntityId;
    }

    private static void customizeEntityDescriptor(EntityDescriptorType entityDescriptor,
        SpidIdentityProviderConfig config)
        throws ConfigurationException
    {
        // Organization
        SpidOrganizationType.build(config).ifPresent(entityDescriptor::setOrganization);

        // ContactPerson type=OTHER
        SpidOtherContactType.build(config).ifPresent(entityDescriptor::addContactPerson);

        // ContactPerson type=BILLING
        SpidBillingContactType.build(config).ifPresent(entityDescriptor::addContactPerson);
    }

    private static void customizeSpDescriptor(SPSSODescriptorType spDescriptor,
        URI loginBinding, URI logoutBinding, 
        List<URI> assertionEndpoints, List<URI> logoutEndpoints)
    {
        // Remove any existing SingleLogoutService endpoints
        List<EndpointType> lstSingleLogoutService = spDescriptor.getSingleLogoutService();
        for (int i = lstSingleLogoutService.size() - 1; i >= 0; --i)
            spDescriptor.removeSingleLogoutService(lstSingleLogoutService.get(i));

        // Add the new SingleLogoutService endpoints
        for (URI logoutEndpoint: logoutEndpoints)
            spDescriptor.addSingleLogoutService(new EndpointType(logoutBinding, logoutEndpoint));

        // Remove any existing AssertionConsumerService endpoints
        List<IndexedEndpointType> lstAssertionConsumerService = spDescriptor.getAssertionConsumerService();
        for (int i = lstAssertionConsumerService.size() - 1; i >= 0; --i)
            spDescriptor.removeAssertionConsumerService(lstAssertionConsumerService.get(i));

        // Add the new AssertionConsumerService endpoints
        int assertionEndpointIndex = 0;
        for (URI assertionEndpoint: assertionEndpoints)
        {
            IndexedEndpointType assertionConsumerEndpoint = new IndexedEndpointType(loginBinding, assertionEndpoint);
            if (assertionEndpointIndex == 0) assertionConsumerEndpoint.setIsDefault(true);
            assertionConsumerEndpoint.setIndex(assertionEndpointIndex);

            spDescriptor.addAssertionConsumerService(assertionConsumerEndpoint);
            assertionEndpointIndex++;
        }
    }

    @Override
    public void close() {
    }

}
