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
        stubOtherContact("", "", "");
        assertEquals(Optional.empty(), SpidOtherContactType.build(config));
    }

    @Test
    void build_withPublicSPConfig_shouldReturnSpidOtherContactTypePublicSP() throws ConfigurationException {
        stubFilledOtherContact(false);
        when(config.getIpaCode()).thenReturn("IPA_manager");
        Optional<SpidOtherContactType> optional = SpidOtherContactType.build(config);
        assertTrue(optional.isPresent());
        assertTrue(optional.get() instanceof SpidOtherContactTypePublicSP);
    }

    @Test
    void build_withPrivateConfig_shouldReturnSpidOtherContactTypePrivateSP() throws ConfigurationException {
        stubFilledOtherContact(true);
        when(config.getVatNumber()).thenReturn("IT01234567890");
        when(config.getFiscalCode()).thenReturn("CF_manager");
        Optional<SpidOtherContactType> optional = SpidOtherContactType.build(config);
        assertTrue(optional.isPresent());
        assertTrue(optional.get() instanceof SpidOtherContactTypePrivateSP);
    }

    private void stubOtherContact(String company, String email, String phone) {
        when(config.getOtherContactCompany()).thenReturn(company);
        when(config.getOtherContactEmail()).thenReturn(email);
        when(config.getOtherContactPhone()).thenReturn(phone);
    }

    private void stubFilledOtherContact(boolean spPrivate) {
        stubOtherContact("Public Company Name", "other_contact@domain.test", "+39 123 456 789");
        when(config.isSpPrivate()).thenReturn(spPrivate);
    }
}
