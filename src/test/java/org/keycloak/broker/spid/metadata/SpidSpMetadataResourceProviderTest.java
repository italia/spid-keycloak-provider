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

package org.keycloak.broker.spid.metadata;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.broker.spid.SpidIdentityProviderFactory;
import org.keycloak.broker.spid.mappers.SpidUserAttributeMapper;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.saml.SamlPrincipalType;
import org.keycloak.saml.common.util.XmlKeyInfoKeyNameTransformer;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlunit.builder.DiffBuilder;
import org.xmlunit.builder.Input;
import org.xmlunit.diff.Diff;
import org.xmlunit.placeholder.PlaceholderDifferenceEvaluator;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import javax.xml.transform.Source;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SpidSpMetadataResourceProviderTest {

    private static final transient Logger log = LoggerFactory.getLogger(SpidSpMetadataResourceProviderTest.class);
    private static final String SP_KEYCLOAK_BASE_URL = "https://keycloak.company.name.it";
    private static KeyWrapper keyWrapper;
    @Mock
    private KeycloakSession keycloakSession;
    @Mock
    private KeycloakSessionFactory keycloakSessionFactory;
    @Mock
    private RealmModel realm;
    @InjectMocks
    private SpidSpMetadataResourceProvider invitationResourceProvider = spy(new SpidSpMetadataResourceProvider(keycloakSession));

    @BeforeAll
    public static void setupKeyWrapper() throws NoSuchAlgorithmException, CertificateEncodingException, SignatureException, NoSuchProviderException, InvalidKeyException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        keyWrapper = new KeyWrapper();
        keyWrapper.setAlgorithm(Algorithm.RS256);
        keyWrapper.setKid(KeyUtils.createKeyId(keyPair.getPublic()));
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setCertificate(generateCertificate(keyPair));
    }

    private static X509Certificate generateCertificate(final KeyPair keyPair) throws CertificateEncodingException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
        CryptoIntegration.init(SpidSpMetadataResourceProviderTest.class.getClassLoader());

        return CryptoIntegration.getProvider().getCertificateUtils()
            .createServicesTestCertificate("CN=Example_CN", 
                new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000),
                new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000), 
                keyPair);
    }

    @BeforeEach
    public void mockKeycloak() {
        try {
            KeycloakContext keycloakContext = mock(KeycloakContext.class);
            when(keycloakSession.getContext()).thenReturn(keycloakContext);
            lenient().when(keycloakSession.getKeycloakSessionFactory()).thenReturn(keycloakSessionFactory);
            KeycloakUriInfo keycloakUriInfo = mock(KeycloakUriInfo.class);
            lenient().when(keycloakUriInfo.getBaseUriBuilder()).thenAnswer(i -> UriBuilder.fromUri(new URI(SP_KEYCLOAK_BASE_URL + "/auth")));
            lenient().when(keycloakContext.getUri()).thenReturn(keycloakUriInfo);
            when(keycloakContext.getRealm()).thenReturn(realm);
            lenient().when(realm.getName()).thenReturn("spid-realm");
            // Mock keys
            KeyManager keyManager = mock(KeyManager.class);
            lenient().when(keycloakSession.keys()).thenReturn(keyManager);
            lenient().when(keyManager.getKeysStream(realm, KeyUse.SIG, Algorithm.RS256)).thenReturn(Stream.of(keyWrapper));
            lenient().when(keyManager.getActiveRsaKey(realm)).thenReturn(
                new KeyManager.ActiveRsaKey(keyWrapper.getKid(), (PrivateKey) keyWrapper.getPrivateKey(), (PublicKey) keyWrapper.getPublicKey(),
                    keyWrapper.getCertificate()));
        } catch (Exception e) {
            log.error("", e);
        }
    }

    @Test
    void get_withoutSPIDIdentityProviders_shouldThrowException() {
        mockSPIDProviders(null);

        RuntimeException runtimeException = assertThrows(RuntimeException.class, () -> {
            invitationResourceProvider.get();
        });

        assertEquals("java.lang.Exception: No SPID providers found!", runtimeException.getMessage());
        assertNotNull(runtimeException.getCause());
        assertEquals("No SPID providers found!", runtimeException.getCause().getMessage());
    }

    @Test
    void get_withPublicSPConfiguration_shouldReturnExpectXml() {
        mockSPIDProviders(mockPublicSPConfig(), "idp1", "idp2");

        Response response = invitationResourceProvider.get();
        assertEquals(200, response.getStatus());
        assertMetaData(response.getEntity().toString(), "/metadata/expected_metadata_public_SP.xml");
    }

    @Test
    void get_withPrivateSPConfiguration_shouldReturnExpectXml() {
        mockSPIDProviders(mockPrivateSPConfig(), "idp1", "idp2");

        Response response = invitationResourceProvider.get();
        assertEquals(200, response.getStatus());
        assertMetaData(response.getEntity().toString(), "/metadata/expected_metadata_private_SP.xml");
    }

    private Map<String, String> mockPublicSPConfig() {
        Map<String, String> providerConfig = mockCommonConfig();
        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_SP_PRIVATE, "false");
        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_IPA_CODE, "IPA_manager");

        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_COMPANY, "Public Company Name");
        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_PHONE, "+39 123 456 789");
        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_EMAIL, "other_contact@domain.test");

        return providerConfig;
    }

    private Map<String, String> mockPrivateSPConfig() {
        Map<String, String> providerConfig = mockCommonConfig();
        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_SP_PRIVATE, "true");

        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_VAT_NUMBER, "IT01234567890");
        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_FISCAL_CODE, "CF_manager");
        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_COMPANY, "Private Company Name");
        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_PHONE, "+39 123 456 789");
        providerConfig.put(SpidIdentityProviderConfig.OTHER_CONTACT_EMAIL, "other_contact@domain.test");

        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_COMPANY, "Billing contact company");
        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_PHONE, "+39 987 654 321");
        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_EMAIL, "billing@domain.test");

        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_REGISTRY_NAME, "Registry Name");
        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_SITE_ADDRESS, "StreetName");
        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_SITE_NUMBER, "111");
        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_SITE_CITY, "City");
        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_SITE_ZIP_CODE, "zip");
        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_SITE_PROVINCE, "Province");
        providerConfig.put(SpidIdentityProviderConfig.BILLING_CONTACT_SITE_COUNTRY, "IT");

        return providerConfig;
    }

    private Map<String, String> mockCommonConfig() {
        Map<String, String> providerConfig = new HashMap();
        // Generic SAML configuration options

        providerConfig.put(SAMLIdentityProviderConfig.ENTITY_ID, SP_KEYCLOAK_BASE_URL);
        providerConfig.put(SAMLIdentityProviderConfig.BACKCHANNEL_SUPPORTED, "false");
        providerConfig.put(SAMLIdentityProviderConfig.NAME_ID_POLICY_FORMAT, "Transient");
        providerConfig.put(SAMLIdentityProviderConfig.PRINCIPAL_TYPE, SamlPrincipalType.ATTRIBUTE.toString());
        providerConfig.put(SAMLIdentityProviderConfig.PRINCIPAL_ATTRIBUTE, "fiscalNumber");
        providerConfig.put(SAMLIdentityProviderConfig.ALLOW_CREATE, "true");
        providerConfig.put(SAMLIdentityProviderConfig.POST_BINDING_RESPONSE, "true");
        providerConfig.put(SAMLIdentityProviderConfig.POST_BINDING_AUTHN_REQUEST, "true");
        providerConfig.put(SAMLIdentityProviderConfig.POST_BINDING_LOGOUT, "true");
        providerConfig.put(SAMLIdentityProviderConfig.WANT_AUTHN_REQUESTS_SIGNED, "true");
        providerConfig.put(SAMLIdentityProviderConfig.WANT_ASSERTIONS_SIGNED, "true");
        providerConfig.put(SAMLIdentityProviderConfig.WANT_ASSERTIONS_ENCRYPTED, "false");
        providerConfig.put(SAMLIdentityProviderConfig.SIGNATURE_ALGORITHM, "RSA_SHA256");
        providerConfig.put(SAMLIdentityProviderConfig.XML_SIG_KEY_INFO_KEY_NAME_TRANSFORMER, XmlKeyInfoKeyNameTransformer.NONE.toString());
        providerConfig.put(SAMLIdentityProviderConfig.FORCE_AUTHN, "false");
        providerConfig.put(SAMLIdentityProviderConfig.VALIDATE_SIGNATURE, "true");
        providerConfig.put(SAMLIdentityProviderConfig.SIGNING_CERTIFICATE_KEY, keyWrapper.getKid());
        providerConfig.put(SAMLIdentityProviderConfig.SIGN_SP_METADATA, "true");
        providerConfig.put(SAMLIdentityProviderConfig.LOGIN_HINT, "false"); // Pass subject
        providerConfig.put(SAMLIdentityProviderConfig.ALLOWED_CLOCK_SKEW, "");
        providerConfig.put(SAMLIdentityProviderConfig.ATTRIBUTE_CONSUMING_SERVICE_INDEX, "1");
        providerConfig.put(SAMLIdentityProviderConfig.ATTRIBUTE_CONSUMING_SERVICE_NAME, "en|Online services,it|Servizi online");

        // SPID specific configuration
        providerConfig.put(SpidIdentityProviderConfig.ORGANIZATION_NAMES, "en|MyCompany srl,it|MyCompany srl");
        providerConfig.put(SpidIdentityProviderConfig.ORGANIZATION_DISPLAY_NAMES, "en|MyCompany,it|MyCompany");
        providerConfig.put(SpidIdentityProviderConfig.ORGANIZATION_URLS, "en|https://company.name.it,it|https://company.name.it");
        return providerConfig;
    }

    private void mockSPIDProviders(Map<String, String> commonConfig, String... aliases) {
        when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(aliases).map(alias -> mockSPIDProvider(commonConfig, alias)));
    }

    private IdentityProviderModel mockSPIDProvider(Map<String, String> commonConfig, String alias) {
        IdentityProviderModel idpModel = mock(IdentityProviderModel.class);
        when(idpModel.getAlias()).thenReturn(alias);
        when(idpModel.getProviderId()).thenReturn(SpidIdentityProviderFactory.PROVIDER_ID);
        when(idpModel.isEnabled()).thenReturn(true);
        Map<String, String> idpConfig = new HashMap();
        idpConfig.putAll(commonConfig);
        idpConfig.put(SAMLIdentityProviderConfig.SINGLE_SIGN_ON_SERVICE_URL, "https://" + alias + ".localtest.me/samlsso/login");
        idpConfig.put(SAMLIdentityProviderConfig.SINGLE_LOGOUT_SERVICE_URL, "https://" + alias + ".localtest.me/samlsso/logout");
        lenient().when(idpModel.getConfig()).thenReturn(idpConfig);
        Stream<IdentityProviderMapperModel> identityProviderMappers = mockAttributeMappers(alias);
        lenient().when(realm.getIdentityProviderMappersByAliasStream(alias)).thenReturn(identityProviderMappers);
        return idpModel;
    }

    private Stream<IdentityProviderMapperModel> mockAttributeMappers(String alias) {
        IdentityProviderMapperModel taxIdMapper = mockSpidUserAttributeMapper(alias, "Tax Id", "fiscalNumber");
        IdentityProviderMapperModel firstNameMapper = mockSpidUserAttributeMapper(alias, "First Name", "name");
        IdentityProviderMapperModel lastNameMapper = mockSpidUserAttributeMapper(alias, "Last Name", "familyName");
        return Stream.of(taxIdMapper, firstNameMapper, lastNameMapper);
    }

    private IdentityProviderMapperModel mockSpidUserAttributeMapper(final String alias, final String name, final String attributeName) {
        IdentityProviderMapperModel spidUserAttributeMapper = new IdentityProviderMapperModel();
        spidUserAttributeMapper.setId(UUID.randomUUID().toString());
        spidUserAttributeMapper.setName(name);
        spidUserAttributeMapper.setIdentityProviderAlias(alias);
        spidUserAttributeMapper.setIdentityProviderMapper(alias + "_" + name);
        Map<String, String> config = new HashMap<>();
        config.put("attribute.name", attributeName);
        config.put("attribute.friendly.name", "");
        spidUserAttributeMapper.setConfig(config);
        lenient().when(keycloakSessionFactory.getProviderFactory(IdentityProviderMapper.class, alias + "_" + name)).thenReturn(new SpidUserAttributeMapper());
        return spidUserAttributeMapper;
    }

    private void assertMetaData(String response, String expectedResource) {
        Source responseMetadata = Input.fromString(response).build();
        Source control = Input.fromStream(this.getClass().getResourceAsStream(expectedResource)).build();

        Diff myDiff = DiffBuilder.compare(control)
            .withTest(responseMetadata)
            .checkForIdentical()
            .ignoreComments()
            .ignoreWhitespace()
            .normalizeWhitespace()
            .withDifferenceEvaluator(new PlaceholderDifferenceEvaluator())
            .build();

        Assertions.assertAll("Found differences in metadata file",
            StreamSupport.stream(myDiff.getDifferences().spliterator(), false)
                .map(diff -> (Executable) (() -> fail(diff.getComparison().toString())))
                .collect(Collectors.<Executable>toList()));

    }
}

