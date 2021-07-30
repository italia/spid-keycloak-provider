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
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.keycloak.dom.saml.v2.metadata.ContactType;
import org.keycloak.dom.saml.v2.metadata.ContactTypeType;
import org.keycloak.dom.saml.v2.metadata.EndpointType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.ExtensionsType;
import org.keycloak.dom.saml.v2.metadata.IndexedEndpointType;
import org.keycloak.dom.saml.v2.metadata.LocalizedNameType;
import org.keycloak.dom.saml.v2.metadata.LocalizedURIType;
import org.keycloak.dom.saml.v2.metadata.OrganizationType;
import org.keycloak.dom.saml.v2.metadata.SPSSODescriptorType;
import org.keycloak.models.KeyManager;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.SPMetadataDescriptor;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;
import org.keycloak.saml.processing.api.saml.v2.sig.SAML2Signature;
import org.keycloak.protocol.saml.SamlService;
import org.keycloak.protocol.saml.mappers.SamlMetadataDescriptorUpdater;
import org.keycloak.services.resource.RealmResourceProvider;

import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
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

    public static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";
    public static final String SPID_METADATA_EXTENSIONS_NS = "https://spid.gov.it/saml-extensions";

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

            // Prepare the metadata descriptor model
            StringWriter sw = new StringWriter();
            XMLStreamWriter writer = StaxUtil.getXMLStreamWriter(sw);
            SAMLMetadataWriter metadataWriter = new SAMLMetadataWriter(writer);

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
                    attributeConsumingServiceNameElement.setValue(parsedName[1]);
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
            String strOrganizationNames = firstSpidProvider.getConfig().getOrganizationNames();
            String[] organizationNames = strOrganizationNames != null ? strOrganizationNames.split(","): null;

            String strOrganizationDisplayNames = firstSpidProvider.getConfig().getOrganizationDisplayNames();
            String[] organizationDisplayNames = strOrganizationDisplayNames != null ? strOrganizationDisplayNames.split(","): null;

            String strOrganizationUrls = firstSpidProvider.getConfig().getOrganizationUrls();
            String[] organizationUrls = strOrganizationUrls != null ? strOrganizationUrls.split(","): null;

            boolean isSpPrivate = firstSpidProvider.getConfig().isSpPrivate();
            String ipaCode = firstSpidProvider.getConfig().getIpaCode();
            String vatNumber = firstSpidProvider.getConfig().getVatNumber();
            String fiscalCode = firstSpidProvider.getConfig().getFiscalCode();
            String otherContactPersonCompany = firstSpidProvider.getConfig().getOtherContactCompany();
            String otherContactPersonEmail = firstSpidProvider.getConfig().getOtherContactEmail();
            String otherContactPersonPhone = firstSpidProvider.getConfig().getOtherContactPhone();
            String billingContactPersonCompany = firstSpidProvider.getConfig().getBillingContactCompany();
            String billingContactPersonEmail = firstSpidProvider.getConfig().getBillingContactEmail(); 
            String billingContactPersonPhone = firstSpidProvider.getConfig().getBillingContactPhone();

			// Additional EntityDescriptor customizations
            customizeEntityDescriptor(entityDescriptor, 
                organizationNames, organizationDisplayNames, organizationUrls,
                isSpPrivate, ipaCode, vatNumber, fiscalCode,
                otherContactPersonCompany, otherContactPersonEmail, otherContactPersonPhone,
                billingContactPersonCompany, billingContactPersonEmail, billingContactPersonPhone);

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

            // Write the metadata and export it to a string
            metadataWriter.writeEntityDescriptor(entityDescriptor);

            String descriptor = sw.toString();

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

    private String getEntityId(String configEntityId, UriInfo uriInfo, RealmModel realm) {
        if (configEntityId == null || configEntityId.isEmpty())
            return UriBuilder.fromUri(uriInfo.getBaseUri()).path("realms").path(realm.getName()).build().toString();
        else
            return configEntityId;
    }

    private static void customizeEntityDescriptor(EntityDescriptorType entityDescriptor,
        String[] organizationNames, String[] organizationDisplayNames, String[] organizationUrls,
        boolean isSpPrivate, String ipaCode, String vatNumber, String fiscalCode,
        String otherContactPersonCompany, String otherContactPersonEmail, String otherContactPersonPhone,
        String billingContactPersonCompany, String billingContactPersonEmail, String billingContactPersonPhone) 
        throws ConfigurationException
    {
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

            // ContactPerson type=OTHER
            if (!StringUtil.isNullOrEmpty(otherContactPersonCompany) || !StringUtil.isNullOrEmpty(otherContactPersonEmail) || !StringUtil.isNullOrEmpty(otherContactPersonPhone)) 
            {
                ContactType otherContactPerson = new ContactType(ContactTypeType.OTHER);

                if (!StringUtil.isNullOrEmpty(otherContactPersonCompany)) otherContactPerson.setCompany(otherContactPersonCompany);
                if (!StringUtil.isNullOrEmpty(otherContactPersonEmail)) otherContactPerson.addEmailAddress(otherContactPersonEmail);
                if (!StringUtil.isNullOrEmpty(otherContactPersonPhone)) otherContactPerson.addTelephone(otherContactPersonPhone);

                // Extensions
                if (otherContactPerson.getExtensions() == null)
                    otherContactPerson.setExtensions(new ExtensionsType());

                Document doc = DocumentUtil.createDocument();

                if (!isSpPrivate)
                {
                    // Public SP Extensions
                        
                    // IPA Code
                    if (!StringUtil.isNullOrEmpty(ipaCode))
                    {
                        Element ipaCodeElement = doc.createElementNS(SPID_METADATA_EXTENSIONS_NS, "spid:IPACode");
                        ipaCodeElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
                        ipaCodeElement.setTextContent(ipaCode);
                        otherContactPerson.getExtensions().addExtension(ipaCodeElement);
                    }
    
                    // Public qualifier
                    Element spTypeElement = doc.createElementNS(SPID_METADATA_EXTENSIONS_NS, "spid:Public");
                    spTypeElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
                    otherContactPerson.getExtensions().addExtension(spTypeElement);
                }
                else
                {
                    // Private SP Extensions
                        
                    // VAT Number
                    if (!StringUtil.isNullOrEmpty(vatNumber))
                    {
                        Element vatNumberElement = doc.createElementNS(SPID_METADATA_EXTENSIONS_NS, "spid:VATNumber");
                        vatNumberElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
                        vatNumberElement.setTextContent(vatNumber);
                        otherContactPerson.getExtensions().addExtension(vatNumberElement);
                    }

                    // Fiscal Code	
                    if (!StringUtil.isNullOrEmpty(fiscalCode))
                    {
                        Element fiscalCodeElement = doc.createElementNS(SPID_METADATA_EXTENSIONS_NS, "spid:FiscalCode");
                        fiscalCodeElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
                        fiscalCodeElement.setTextContent(fiscalCode);
                        otherContactPerson.getExtensions().addExtension(fiscalCodeElement);
                    }

                    // Private qualifier
                    Element spTypeElement = doc.createElementNS(SPID_METADATA_EXTENSIONS_NS, "spid:Private");
                    spTypeElement.setAttributeNS(XMLNS_NS, "xmlns:spid", SPID_METADATA_EXTENSIONS_NS);
                    otherContactPerson.getExtensions().addExtension(spTypeElement);
                }

                entityDescriptor.addContactPerson(otherContactPerson);
            }

            // ContactPerson type=BILLING
            if (!StringUtil.isNullOrEmpty(billingContactPersonCompany) || !StringUtil.isNullOrEmpty(billingContactPersonEmail) || !StringUtil.isNullOrEmpty(billingContactPersonPhone)) {
                ContactType billingContactPerson = new ContactType(ContactTypeType.BILLING);

                if (!StringUtil.isNullOrEmpty(billingContactPersonCompany)) billingContactPerson.setCompany(billingContactPersonCompany);
                if (!StringUtil.isNullOrEmpty(billingContactPersonEmail)) billingContactPerson.addEmailAddress(billingContactPersonEmail);
                if (!StringUtil.isNullOrEmpty(billingContactPersonPhone)) billingContactPerson.addTelephone(billingContactPersonPhone);

                entityDescriptor.addContactPerson(billingContactPerson);
            }

            entityDescriptor.setOrganization(organizationType);
        }
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
