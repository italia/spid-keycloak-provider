package org.keycloak.broker.spid.metadata.extensions;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.saml.common.exceptions.ConfigurationException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpidBillingContactTypeTest {

    private SpidIdentityProviderConfig config = mock(SpidIdentityProviderConfig.class);

    @Test
    void build_withoutConfiguration_shouldReturnEmpty() throws ConfigurationException {
        assertEquals(Optional.empty(), SpidBillingContactType.build(config));
    }

    @Test
    void build_withBlanks_shouldReturnEmpty() throws ConfigurationException {
        stubBillingContact("", "", "");
        assertEquals(Optional.empty(), SpidBillingContactType.build(config));
    }

    @Test
    void build_withPublicSP_shouldReturnEmpty() throws ConfigurationException {
        stubFilledBillingContact(false);
        assertEquals(Optional.empty(), SpidBillingContactType.build(config));
    }

    @Test
    void build_withPrivateSP_shouldReturnSpidBillingContactTypePrivateSP() throws ConfigurationException {
        stubFilledBillingContact(true);
        Optional<SpidBillingContactType> optionalBilling = SpidBillingContactType.build(config);
        assertTrue(optionalBilling.isPresent());
        assertTrue(optionalBilling.get() instanceof SpidBillingContactTypePrivateSP);
    }

    @Test
    void build_withPrivateSPAllData_shouldReturnSpidBillingContactTypePrivateSP() throws ConfigurationException {
        stubFilledBillingContact(true);
        when(config.getBillingContactRegistryName()).thenReturn("Registry Name");
        when(config.getBillingContactSiteAddress()).thenReturn("StreetName");
        when(config.getBillingContactSiteNumber()).thenReturn("111");
        when(config.getBillingContactSiteCity()).thenReturn("City");
        when(config.getBillingContactSiteZipCode()).thenReturn("zip");
        when(config.getBillingContactSiteProvince()).thenReturn("Province");
        when(config.getBillingContactSiteCountry()).thenReturn("IT");
        Optional<SpidBillingContactType> optionalBilling = SpidBillingContactType.build(config);
        assertTrue(optionalBilling.isPresent());
        assertTrue(optionalBilling.get() instanceof SpidBillingContactTypePrivateSP);
    }

    private void stubBillingContact(String company, String email, String phone) {
        when(config.getBillingContactCompany()).thenReturn(company);
        when(config.getBillingContactEmail()).thenReturn(email);
        when(config.getBillingContactPhone()).thenReturn(phone);
    }

    private void stubFilledBillingContact(boolean spPrivate) {
        stubBillingContact("Billing contact company", "billing@domain.test", "+39 987 654 321");
        when(config.isSpPrivate()).thenReturn(spPrivate);
    }
}
