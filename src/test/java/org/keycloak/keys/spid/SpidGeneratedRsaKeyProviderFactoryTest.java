package org.keycloak.keys.spid;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.keys.Attributes;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class SpidGeneratedRsaKeyProviderFactoryTest {
    @Mock
    private KeycloakSession session;

    @Mock
    private RealmModel realm;

    @Mock
    private KeycloakContext context;

    @InjectMocks
    private SpidGeneratedRsaKeyProviderFactory factory;

    @BeforeAll
    public static void beforeAll() {
        CryptoIntegration.init(SpidGeneratedRsaKeyProviderFactoryTest.class.getClassLoader());
    }

    @BeforeEach
    public void setUp() {
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(realm.getName()).thenReturn("test-realm");
        lenient().when(realm.getId()).thenReturn("test-realm-id");
    }

    @Test
    void validateConfiguration_withExistingMatchingKeyMaterial_shouldPass() {
        ComponentModel model = buildValidModel();

        assertDoesNotThrow(() -> factory.validateConfiguration(session, realm, model));
    }

    @Test
    void validateConfiguration_withValidConfiguration_shouldGeneratePrivateKeyAndCertificate() {
        ComponentModel model = buildValidModel();

        factory.validateConfiguration(session, realm, model);

        assertNotNull(model.get(Attributes.PRIVATE_KEY_KEY));
        assertNotNull(model.get(Attributes.CERTIFICATE_KEY));
    }

    @Test
    void validateConfiguration_withKeySizeLowerThan2048_shouldThrowValidationException() {
        ComponentModel model = buildValidModel();
        model.put(Attributes.KEY_SIZE_KEY, "1024");

        ComponentValidationException ex = assertThrows(ComponentValidationException.class,
            () -> factory.validateConfiguration(session, realm, model));

        assertEquals("Key size must be at least 2048 bits", ex.getMessage());
    }

    @Test
    void validateConfiguration_withInvalidEntityId_shouldThrowValidationException() {
        ComponentModel model = buildValidModel();
        model.put(SpidAttributes.ENTITY_ID_KEY, "not-a-url");

        ComponentValidationException ex = assertThrows(ComponentValidationException.class,
            () -> factory.validateConfiguration(session, realm, model));

        assertEquals("Entity ID must be a valid URL", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void validateConfiguration_withInvalidCountryLength_shouldThrowValidationException() {
        ComponentModel model = buildValidModel();
        model.put(SpidAttributes.COUNTRY_KEY, "ITA");

        ComponentValidationException ex = assertThrows(ComponentValidationException.class,
            () -> factory.validateConfiguration(session, realm, model));

        assertEquals("Country must be exactly 2 characters long, according to ISO 3166-1 alpha-2 standard", ex.getMessage());
    }

    @Test
    void validateConfiguration_withMissingRequiredField_shouldThrowValidationException() {
        ComponentModel model = buildValidModel();
        model.getConfig().remove(SpidAttributes.COMMON_NAME_KEY);

        assertThrows(ComponentValidationException.class, () -> factory.validateConfiguration(session, realm, model));
    }

    @Test
    void createFallbackKeys_withSigAndSupportedAlgorithm_shouldAddComponentAndReturnTrue() {
        doReturn(new ComponentModel()).when(realm).addComponentModel(any(ComponentModel.class));

        boolean created = factory.createFallbackKeys(session, KeyUse.SIG, Algorithm.RS256);

        assertTrue(created);
        verify(realm).addComponentModel(any(ComponentModel.class));
    }

    @Test
    void createFallbackKeys_withUnsupportedAlgorithm_shouldReturnFalse() {
        boolean created = factory.createFallbackKeys(session, KeyUse.SIG, "HS256");

        assertFalse(created);
    }

    @Test
    void createFallbackKeys_withEncKeyUse_shouldReturnFalse() {
        boolean created = factory.createFallbackKeys(session, KeyUse.ENC, Algorithm.RS256);

        assertFalse(created);
    }

    @Test
    void create_withMissingKeyUse_shouldSetSigAsDefault() {
        ComponentModel model = new ComponentModel();
        model.setConfig(new MultivaluedHashMap<>());

        assertThrows(RuntimeException.class, () -> factory.create(session, model));

        assertEquals(KeyUse.SIG.name(), model.get(Attributes.KEY_USE));
    }

    @Test
    void create_withExistingKeyUse_shouldKeepConfiguredValue() {
        ComponentModel model = new ComponentModel();
        model.setConfig(new MultivaluedHashMap<>());
        model.put(Attributes.KEY_USE, KeyUse.ENC.name());

        assertThrows(RuntimeException.class, () -> factory.create(session, model));

        assertEquals(KeyUse.ENC.name(), model.get(Attributes.KEY_USE));
    }

    private ComponentModel buildValidModel() {
        ComponentModel model = new ComponentModel();
        model.setName("spid-rsa");
        model.setConfig(new MultivaluedHashMap<>());
        model.put(Attributes.KEY_SIZE_KEY, "2048");
        model.put(SpidAttributes.COMMON_NAME_KEY, "Comune di Test");
        model.put(SpidAttributes.ORGANIZATION_NAME_KEY, "Comune di Test Organization");
        model.put(SpidAttributes.ENTITY_ID_KEY, "https://spid-test.example.org/entity");
        model.put(SpidAttributes.IPA_CODE_KEY, "c_h501");
        model.put(SpidAttributes.COUNTRY_KEY, "IT");
        model.put(SpidAttributes.LOCALITY_KEY, "Roma");
        return model;
    }

    @Test
    void validateConfiguration_withValidConfiguration_shouldGenerateCertificateWithCorrectSubject() {
        ComponentModel model = buildValidModel();
        factory.validateConfiguration(session, realm, model);
        KeyWrapper keyWrapper = factory
            .create(session, model)
            .getKeysStream()
            .findFirst()
            .orElseThrow(() -> new RuntimeException("No keys generated by provider"));
        
        X509Certificate certificate = keyWrapper.getCertificate();
        model.put(Attributes.PRIVATE_KEY_KEY, PemUtils.encodeKey(keyWrapper.getPrivateKey()));
        model.put(Attributes.CERTIFICATE_KEY, PemUtils.encodeCertificate(certificate));
        String subject = certificate.getSubjectX500Principal().getName();
        assertTrue(subject.contains("CN=Comune di Test"));
    }
}
