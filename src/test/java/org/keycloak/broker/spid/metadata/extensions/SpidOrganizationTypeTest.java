package org.keycloak.broker.spid.metadata.extensions;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.dom.saml.v2.metadata.OrganizationType;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpidOrganizationTypeTest {

    private SpidIdentityProviderConfig config = mock(SpidIdentityProviderConfig.class);

    @Test
    void build_withoutConfiguration_shouldReturnEmpty() {
        assertEquals(Optional.empty(), SpidOrganizationType.build(config));
    }

    @Test
    void build_withBlanks_shouldReturnEmpty() {
        when(config.getOrganizationNames()).thenReturn("");
        when(config.getOrganizationDisplayNames()).thenReturn("");
        when(config.getOrganizationDisplayNames()).thenReturn("");
        assertEquals(Optional.empty(), SpidOrganizationType.build(config));
    }

    @Test
    void build_withNames_shouldReturnOrganizationType() {
        when(config.getOrganizationNames()).thenReturn("en|MyCompany en srl,it|MyCompany it srl");
        Optional<OrganizationType> type = SpidOrganizationType.build(config);
        assertTrue(type.isPresent());
        assertEquals(2, type.get().getOrganizationName().size());
        assertEquals("en", type.get().getOrganizationName().get(0).getLang());
        assertEquals("MyCompany en srl", type.get().getOrganizationName().get(0).getValue());
        assertEquals("it", type.get().getOrganizationName().get(1).getLang());
        assertEquals("MyCompany it srl", type.get().getOrganizationName().get(1).getValue());
    }

    @Test
    void build_withNamesWithoutLanguagePrefix_dropsName() {
        when(config.getOrganizationNames()).thenReturn("MyCompany en srl");
        Optional<OrganizationType> type = SpidOrganizationType.build(config);
        assertTrue(type.isPresent());
        assertEquals(0, type.get().getOrganizationName().size());
    }

    @Test
    void build_withDisplayNames_shouldReturnOrganizationType() {
        when(config.getOrganizationDisplayNames()).thenReturn("en|MyCompany1,it|MyCompany2");
        Optional<OrganizationType> type = SpidOrganizationType.build(config);
        assertTrue(type.isPresent());
        assertEquals(2, type.get().getOrganizationDisplayName().size());
        assertEquals("en", type.get().getOrganizationDisplayName().get(0).getLang());
        assertEquals("MyCompany1", type.get().getOrganizationDisplayName().get(0).getValue());
        assertEquals("it", type.get().getOrganizationDisplayName().get(1).getLang());
        assertEquals("MyCompany2", type.get().getOrganizationDisplayName().get(1).getValue());
    }

    @Test
    void build_withDisplayNamesWithoutLanguagePrefix_dropsName() {
        when(config.getOrganizationNames()).thenReturn("MyCompany srl");
        Optional<OrganizationType> type = SpidOrganizationType.build(config);
        assertTrue(type.isPresent());
        assertEquals(0, type.get().getOrganizationDisplayName().size());
    }

    @Test
    void build_withUrls_shouldReturnOrganizationType() {
        when(config.getOrganizationUrls()).thenReturn("en|https://company.name.en,it|https://company.name.it");
        Optional<OrganizationType> type = SpidOrganizationType.build(config);
        assertTrue(type.isPresent());
        assertEquals(2, type.get().getOrganizationURL().size());
        assertEquals("en", type.get().getOrganizationURL().get(0).getLang());
        assertEquals("https://company.name.en", type.get().getOrganizationURL().get(0).getValue().toString());
        assertEquals("it", type.get().getOrganizationURL().get(1).getLang());
        assertEquals("https://company.name.it", type.get().getOrganizationURL().get(1).getValue().toString());
    }

    @Test
    void build_withUrlsWithoutLanguagePrefix_dropsName() {
        when(config.getOrganizationNames()).thenReturn("https://company.name.it");
        Optional<OrganizationType> type = SpidOrganizationType.build(config);
        assertTrue(type.isPresent());
        assertEquals(0, type.get().getOrganizationURL().size());
    }
}
