package org.keycloak.keys.spid;

import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.keycloak.Config;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.keys.AbstractRsaKeyProvider;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.GeneratedRsaKeyProviderFactory;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;

public class SpidGeneratedRsaKeyProviderFactory implements KeyProviderFactory {
    public static final String ID = "spid-rsa-generated";
    private static final String[] CERTIFICATE_POLICY_IDENTIFIERS = {
        "1.3.76.16",        // AgIDroot
        "1.3.76.16.6",      // agIDcert
        "1.3.76.16.4.2.1",  // cert_SP_Pub
    };
    private static final int MIN_KEY_SIZE = 2048; // SPID specifications require a minimum key size of 2048 bits
    private static final Logger logger = Logger.getLogger(GeneratedRsaKeyProviderFactory.class);
    private static final String HELP_TEXT = "Generates RSA signature keys and creates a self-signed certificate for public entities, compliant with the SPID specifications.";
    private int defaultKeySize = MIN_KEY_SIZE;

    private final static ProviderConfigurationBuilder configurationBuilder() {
        ProviderConfigProperty keySize = Attributes.KEY_SIZE_PROPERTY.get();
        keySize.setDefaultValue(MIN_KEY_SIZE);
        keySize.setOptions(keySize.getOptions().stream().filter(option -> Integer.parseInt(option) >= MIN_KEY_SIZE).collect(Collectors.toList()));
        return ProviderConfigurationBuilder.create()
            .property(Attributes.PRIORITY_PROPERTY)
            .property(Attributes.ENABLED_PROPERTY)
            .property(Attributes.ACTIVE_PROPERTY)
            .property(SpidAttributes.ALGORITHM_PROPERTY.get())
            .property(keySize)
            .property(SpidAttributes.COMMON_NAME_PROPERTY.get())
            .property(SpidAttributes.ORGANIZATION_NAME_PROPERTY.get())
            .property(SpidAttributes.ENTITY_ID_PROPERTY.get())
            .property(SpidAttributes.IPA_CODE_PROPERTY.get())
            .property(SpidAttributes.COUNTRY_PROPERTY.get())
            .property(SpidAttributes.LOCALITY_PROPERTY.get());
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        ConfigurationValidationHelper.check(model)
            .checkLong(Attributes.PRIORITY_PROPERTY, false)
            .checkBoolean(Attributes.ENABLED_PROPERTY, false)
            .checkBoolean(Attributes.ACTIVE_PROPERTY, false)
            .checkList(Attributes.KEY_SIZE_PROPERTY.get(), false)
            .checkRequired(SpidAttributes.COMMON_NAME_PROPERTY.get())
            .checkRequired(SpidAttributes.ORGANIZATION_NAME_PROPERTY.get())
            .checkRequired(SpidAttributes.ENTITY_ID_PROPERTY.get())
            .checkRequired(SpidAttributes.IPA_CODE_PROPERTY.get())
            .checkRequired(SpidAttributes.COUNTRY_PROPERTY.get())
            .checkRequired(SpidAttributes.LOCALITY_PROPERTY.get());
        final int size = model.get(Attributes.KEY_SIZE_KEY, this.defaultKeySize);
        if (size < MIN_KEY_SIZE) {
            throw new ComponentValidationException("Key size must be at least " + MIN_KEY_SIZE + " bits");
        }
        final String commonName = model.get(SpidAttributes.COMMON_NAME_KEY);
        final String organizationName = model.get(SpidAttributes.ORGANIZATION_NAME_KEY);
        final String entityId = model.get(SpidAttributes.ENTITY_ID_KEY);
        try {
            if (!new URL(entityId).toURI().isAbsolute()) {
                throw new ComponentValidationException("Entity ID must be a valid absolute URL");
            }
        } catch (Exception e) {
            throw new ComponentValidationException("Entity ID must be a valid URL", e);
        }
        final String ipaCode = model.get(SpidAttributes.IPA_CODE_KEY);
        final String country = model.get(SpidAttributes.COUNTRY_KEY);
        if (country.length() != 2) {
            throw new ComponentValidationException("Country must be exactly 2 characters long, according to ISO 3166-1 alpha-2 standard");
        }
        final String locality = model.get(SpidAttributes.LOCALITY_KEY);
        if (!(model.contains(Attributes.PRIVATE_KEY_KEY) && model.contains(Attributes.CERTIFICATE_KEY))) {
            generateKeys(realm, model, size, commonName, organizationName, entityId, ipaCode, country, locality);

            logger.debugv("Generated keys for {0}", realm.getName());
        } else {
            PrivateKey privateKey = PemUtils.decodePrivateKey(model.get(Attributes.PRIVATE_KEY_KEY));
            int currentSize = ((RSAPrivateKey) privateKey).getModulus().bitLength();
            if (currentSize != size) {
                generateKeys(realm, model, size, commonName, organizationName, entityId, ipaCode, country, locality);

                logger.debugv("Key size changed, generating new keys for {0}", realm.getName());
            }
        }
    }
    
    @Override
    public void init(Config.Scope config) {
        this.defaultKeySize = config.getInt(Attributes.KEY_SIZE_KEY, this.defaultKeySize);
    }

    @Override
    public boolean createFallbackKeys(KeycloakSession session, KeyUse keyUse, String algorithm) {
        if (isValidKeyUse(keyUse) && isSupportedRsaAlgorithm(algorithm)) {
            RealmModel realm = session.getContext().getRealm();

            ComponentModel generated = new ComponentModel();
            generated.setName("fallback-" + algorithm);
            generated.setParentId(realm.getId());
            generated.setProviderId(getId());
            generated.setProviderType(KeyProvider.class.getName());

            MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
            config.putSingle(Attributes.PRIORITY_KEY, "-100");
            config.putSingle(Attributes.ALGORITHM_KEY, algorithm);
            generated.setConfig(config);

            realm.addComponentModel(generated);

            return true;
        } else {
            return false;
        }
    }

    private void generateKeys(RealmModel realm, ComponentModel model, int size, String commonName, String organizationName, String entityId, String ipaCode, String country, String locality) {
        KeyPair keyPair;
        try {
            keyPair = KeyUtils.generateRsaKeyPair(size);
            model.put(Attributes.PRIVATE_KEY_KEY, PemUtils.encodeKey(keyPair.getPrivate()));
        } catch (Throwable t) {
            logger.warnf("Failed to generate keys for key provider '%s' in realm '%s'. Details: %s", model.getName(), realm.getName(), t.getMessage());
            if (logger.isDebugEnabled()) {
                logger.debug(t.getMessage(), t);
            }
            throw new ComponentValidationException("Failed to generate keys", t);
        }

        generateCertificate(realm, model, keyPair, commonName, organizationName, entityId, ipaCode, country, locality);
    }

    private void generateCertificate(RealmModel realm, ComponentModel model, KeyPair keyPair, String commonName, String organizationName, String entityId, String ipaCode, String country, String locality) {
        try {
            Date validityStartDate = new Date(System.currentTimeMillis() - 100000);
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.YEAR, 10);
            String subject = getCertificateSubject(commonName, organizationName, entityId, ipaCode, country, locality);
            Certificate certificate = CryptoIntegration.getProvider().getCertificateUtils().createServicesTestCertificate(
                subject,
                validityStartDate,
                calendar.getTime(),
                keyPair,
                CERTIFICATE_POLICY_IDENTIFIERS
            );
            model.put(Attributes.CERTIFICATE_KEY, PemUtils.encodeCertificate(certificate));
        } catch (Throwable t) {
            logger.warnf("Failed to generate certificate for key provider '%s' in realm '%s'. Details: %s", model.getName(), realm.getName(), t.getMessage());
            if (logger.isDebugEnabled()) {
                logger.debug(t.getMessage(), t);
            }
            throw new ComponentValidationException("Failed to generate certificate", t);
        }
    }

    @Override
    public KeyProvider create(KeycloakSession session, ComponentModel model) {
        if (model.getConfig().get(Attributes.KEY_USE) == null) {
            // for backward compatibility : it allows "enc" key use for "rsa-generated" provider
            model.put(Attributes.KEY_USE, KeyUse.SIG.name());
        }
        return new AbstractRsaKeyProvider(session.getContext().getRealm(), model){};
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configurationBuilder()
            .build();
    }

    @Override
    public String getId() {
        return ID;
    }

    private boolean isValidKeyUse(KeyUse keyUse) {
        return keyUse.equals(KeyUse.SIG);
    }

    private boolean isSupportedRsaAlgorithm(String algorithm) {
        return algorithm.equals(Algorithm.RS256)
            || algorithm.equals(Algorithm.RS512);
    }

    private String getCertificateSubject(String commonName, String organizationName, String entityId, String ipaCode, String country, String locality) {
        return String.format(
            "CN=%s, O=%s, 2.5.4.83=%s, 2.5.4.97=PA:IT-%s, C=%s, L=%s",
            commonName.replace(",", "\\,").trim(),
            organizationName.replace(",", "\\,").trim(),
            entityId.replace(",", "\\,").trim(),
            ipaCode.replace(",", "\\,").trim(),
            country.replace(",", "\\,").trim(),
            locality.replace(",", "\\,").trim()
        );
    }
}
