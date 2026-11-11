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
        setupSpidIdentityProviderConfigGetBillingContactEmailAnd2MoreStubs("", "", "");
        assertEquals(Optional.empty(), SpidBillingContactType.build(config));
    }

    @Test
    void build_withPublicSP_shouldReturnEmpty() throws ConfigurationException {
        setupSpidIdentityProviderConfigGetBillingContactCompanyAnd3MoreStubs(false);
        assertEquals(Optional.empty(), SpidBillingContactType.build(config));
    }

    @Test
    void build_withPrivateSP_shouldReturnSpidBillingContactTypePrivateSP() throws ConfigurationException {
        setupSpidIdentityProviderConfigGetBillingContactCompanyAnd3MoreStubs(true);
        Optional<SpidBillingContactType> optionalBilling = SpidBillingContactType.build(config);
        assertTrue(optionalBilling.isPresent());
        assertTrue(optionalBilling.get() instanceof SpidBillingContactTypePrivateSP);
    }

    @Test
    void build_withPrivateSPAllData_shouldReturnSpidBillingContactTypePrivateSP() throws ConfigurationException {
        setupSpidIdentityProviderConfigGetBillingContactCompanyAnd3MoreStubs(true);
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

    private void setupSpidIdentityProviderConfigGetBillingContactEmailAnd2MoreStubs(String getBillingContactEmailReturnValue, String getBillingContactPhoneReturnValue, String getBillingContactCompanyReturnValue) {
        when(config.getBillingContactCompany()).thenReturn(getBillingContactCompanyReturnValue);
        when(config.getBillingContactEmail()).thenReturn(getBillingContactEmailReturnValue);
        when(config.getBillingContactPhone()).thenReturn(getBillingContactPhoneReturnValue);
    }

    private void setupSpidIdentityProviderConfigGetBillingContactCompanyAnd3MoreStubs(boolean isSpPrivateReturnValue) {
        setupSpidIdentityProviderConfigGetBillingContactEmailAnd2MoreStubs("billing@domain.test", "+39 987 654 321", "Billing contact company");
        when(config.isSpPrivate()).thenReturn(isSpPrivateReturnValue);
    }
}
