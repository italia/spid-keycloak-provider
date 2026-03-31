package org.keycloak.keys.spid;

import java.util.function.Supplier;

import org.keycloak.crypto.Algorithm;
import org.keycloak.keys.Attributes;
import org.keycloak.provider.ProviderConfigProperty;

public interface SpidAttributes {
    String COMMON_NAME_KEY = "spidCommonName";
    String ORGANIZATION_NAME_KEY = "spidOrganizationName";
    String ENTITY_ID_KEY = "spidEntityId";
    String IPA_CODE_KEY = "spidIpaCode";
    String COUNTRY_KEY = "spidCountry";
    String LOCALITY_KEY = "spidLocality";
    Supplier<ProviderConfigProperty> COMMON_NAME_PROPERTY = () -> new ProviderConfigProperty(
        COMMON_NAME_KEY,
        "Common Name",
        "La denominazione che valorizza l’estensione organizationName, eventualmente senza esplicitazione degli acronimi, come riportata nel tag XML <OrganizationDisplayName> del metadata del SP (esempio: “AgID”).",
        ProviderConfigProperty.STRING_TYPE,
        null
    );
    Supplier<ProviderConfigProperty> ORGANIZATION_NAME_PROPERTY = () -> new ProviderConfigProperty(
        ORGANIZATION_NAME_KEY,
        "Organization Name",
        "Denominazione completa e per esteso del SP, così indicata nei pubblici registri e come riportata nel tag xml <OrganizationName> del metadata del SP (esempio: “Comune di Forlì” e non “COMUNE DI FORLI”).",
        ProviderConfigProperty.STRING_TYPE,
        null
    );
    Supplier<ProviderConfigProperty> ENTITY_ID_PROPERTY = () -> new ProviderConfigProperty(
        ENTITY_ID_KEY,
        "Entity ID",
        "EntityID del Service Provider, ovvero un url univoco che identifica il SP.",
        ProviderConfigProperty.STRING_TYPE,
        null
    );
    Supplier<ProviderConfigProperty> IPA_CODE_PROPERTY = () -> new ProviderConfigProperty(
        IPA_CODE_KEY,
        "IPA Code",
        "Codice IPA dell'ente. Ad esempio, per il Comune di Roma il codice ipa è ‘c_h501’.",
        ProviderConfigProperty.STRING_TYPE,
        null
    );
    Supplier<ProviderConfigProperty> COUNTRY_PROPERTY = () -> new ProviderConfigProperty(
        COUNTRY_KEY,
        "Country",
        "Il codice ISO 3166-1 del Paese ove è situata la sede legale del SP (esempio: “IT”).",
        ProviderConfigProperty.STRING_TYPE,
        null
    );
    Supplier<ProviderConfigProperty> LOCALITY_PROPERTY = () -> new ProviderConfigProperty(
        LOCALITY_KEY,
        "Locality",
        "Il nome completo della città ove è situata la sede legale del SP (esempio: Forlì e non Forli”).",
        ProviderConfigProperty.STRING_TYPE,
        null
    );
    Supplier<ProviderConfigProperty> ALGORITHM_PROPERTY = () -> new ProviderConfigProperty(
        Attributes.ALGORITHM_KEY,
        "Algorithm",
        "L’algoritmo impiegato per le impronte crittografiche è il dedicated hash-function 4 definito nella norma ISO/IEC 10118-3, corrispondente alla funzione sha-256. È consentito l’uso della funzione sha-512.",
        ProviderConfigProperty.LIST_TYPE,
        Algorithm.RS256,
        Algorithm.RS256, Algorithm.RS512);
}
