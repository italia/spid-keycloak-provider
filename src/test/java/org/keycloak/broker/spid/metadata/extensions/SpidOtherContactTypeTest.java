package org.keycloak.broker.spid.metadata.extensions;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.saml.common.exceptions.ConfigurationException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpidOtherContactTypeTest {

    private SpidIdentityProviderConfig config = mock(SpidIdentityProviderConfig.class);

    @Test
    void build_withoutConfiguration_shouldReturnEmpty() throws ConfigurationException {
        assertEquals(Optional.empty(), SpidOtherContactType.build(config));
    }

    @Test
    void build_withBlanks_shouldReturnEmpty() throws ConfigurationException {
        when(config.getOtherContactCompany()).thenReturn("");
        when(config.getOtherContactEmail()).thenReturn("");
        when(config.getOtherContactPhone()).thenReturn("");
        assertEquals(Optional.empty(), SpidOtherContactType.build(config));
    }

    @Test
    void build_withPublicSPConfig_shouldReturnSpidOtherContactTypePublicSP() throws ConfigurationException {
        when(config.getOtherContactCompany()).thenReturn("Public Company Name");
        when(config.getOtherContactEmail()).thenReturn("other_contact@domain.test");
        when(config.getOtherContactPhone()).thenReturn("+39 123 456 789");
        when(config.isSpPrivate()).thenReturn(false);
        when(config.getIpaCode()).thenReturn("IPA_manager");
        Optional<SpidOtherContactType> optional = SpidOtherContactType.build(config);
        assertTrue(optional.isPresent());
        assertTrue(optional.get() instanceof SpidOtherContactTypePublicSP);
    }

    @Test
    void build_withPrivateConfig_shouldReturnSpidOtherContactTypePrivateSP() throws ConfigurationException {
        when(config.getOtherContactCompany()).thenReturn("Public Company Name");
        when(config.getOtherContactEmail()).thenReturn("other_contact@domain.test");
        when(config.getOtherContactPhone()).thenReturn("+39 123 456 789");
        when(config.isSpPrivate()).thenReturn(true);
        when(config.getVatNumber()).thenReturn("IT01234567890");
        when(config.getFiscalCode()).thenReturn("CF_manager");
        Optional<SpidOtherContactType> optional = SpidOtherContactType.build(config);
        assertTrue(optional.isPresent());
        assertTrue(optional.get() instanceof SpidOtherContactTypePrivateSP);
    }
}
