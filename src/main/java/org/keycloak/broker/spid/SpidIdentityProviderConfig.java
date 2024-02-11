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
package org.keycloak.broker.spid;

import java.util.List;

import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class SpidIdentityProviderConfig extends SAMLIdentityProviderConfig  {

    public static final String ORGANIZATION_NAMES = "organizationNames";
    public static final String IDP_ENTITY_ID = "idpEntityId";
    public static final String ORGANIZATION_DISPLAY_NAMES = "organizationDisplayNames";
    public static final String ORGANIZATION_URLS = "organizationUrls";
    public static final String OTHER_CONTACT_SP_PRIVATE = "otherContactIsSpPrivate";
    public static final String OTHER_CONTACT_IPA_CODE = "otherContactIpaCode";
    public static final String OTHER_CONTACT_VAT_NUMBER = "otherContactVatNumber";
    public static final String OTHER_CONTACT_FISCAL_CODE = "otherContactFiscalCode";
    public static final String OTHER_CONTACT_COMPANY = "otherContactCompany";
    public static final String OTHER_CONTACT_PHONE = "otherContactPhone";
    public static final String OTHER_CONTACT_EMAIL = "otherContactEmail";
    public static final String BILLING_CONTACT_COMPANY = "billingContactCompany";
    public static final String BILLING_CONTACT_PHONE = "billingContactPhone";
    public static final String BILLING_CONTACT_EMAIL = "billingContactEmail";
    public static final String BILLING_CONTACT_REGISTRY_NAME = "billingContactRegistryName";
    public static final String BILLING_CONTACT_SITE_ADDRESS = "billingContactSiteAddress";
    public static final String BILLING_CONTACT_SITE_NUMBER = "billingContactSiteNumber";
    public static final String BILLING_CONTACT_SITE_CITY = "billingContactSiteCity";
    public static final String BILLING_CONTACT_SITE_ZIP_CODE = "billingContactSiteZipCode";
    public static final String BILLING_CONTACT_SITE_PROVINCE = "billingContactSiteProvince";
    public static final String BILLING_CONTACT_SITE_COUNTRY = "billingContactSiteCountry";
    public static final String SPID_RESPONSE_DEBUG_ENABLED = "debugEnabled";

    public SpidIdentityProviderConfig(){
    }

    public SpidIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }

    public String getIdpEntityId() {
        return getConfig().get(IDP_ENTITY_ID);
    }

    public void setIdpEntityId(String idpEntityId) {
        getConfig().put(IDP_ENTITY_ID, idpEntityId);
    }

    public String getOrganizationNames() {
        return getConfig().get(ORGANIZATION_NAMES);
    }

    public void setOrganizationNames(String organizationNames) {
        getConfig().put(ORGANIZATION_NAMES, organizationNames);
    }

    public String getOrganizationDisplayNames() {
        return getConfig().get(ORGANIZATION_DISPLAY_NAMES);
    }

    public void setOrganizationDisplayNames(String organizationDisplayNames) {
        getConfig().put(ORGANIZATION_DISPLAY_NAMES, organizationDisplayNames);
    }

    public String getOrganizationUrls() {
        return getConfig().get(ORGANIZATION_URLS);
    }

    public void setOrganizationUrls(String organizationUrls) {
        getConfig().put(ORGANIZATION_URLS, organizationUrls);
    }

    public boolean isSpPrivate() {
        return Boolean.valueOf(getConfig().get(OTHER_CONTACT_SP_PRIVATE));
    }

    public void setSpPrivate(boolean isPrivate) {
        getConfig().put(OTHER_CONTACT_SP_PRIVATE, String.valueOf(isPrivate));
    }

    public String getIpaCode() {
        return getConfig().get(OTHER_CONTACT_IPA_CODE);
    }

    public void setIpaCode(String ipaCode) {
        getConfig().put(OTHER_CONTACT_IPA_CODE, ipaCode);
    }

    public String getVatNumber() {
        return getConfig().get(OTHER_CONTACT_VAT_NUMBER);
    }

    public void setVatNumber(String vatNumber) {
        getConfig().put(OTHER_CONTACT_VAT_NUMBER, vatNumber);
    }

    public String getFiscalCode() {
        return getConfig().get(OTHER_CONTACT_FISCAL_CODE);
    }

    public void setFiscalCode(String fiscalCode) {
        getConfig().put(OTHER_CONTACT_FISCAL_CODE, fiscalCode);
    }

    public String getOtherContactEmail() {
        return getConfig().get(OTHER_CONTACT_EMAIL);
    }

    public String getOtherContactCompany() {
        return getConfig().get(OTHER_CONTACT_COMPANY);
    }

    public String getOtherContactPhone() {
        return getConfig().get(OTHER_CONTACT_PHONE);
    }

    public void setOtherContactEmail(String contactEmail) {
        getConfig().put(OTHER_CONTACT_EMAIL, contactEmail);
    }

    public void setOtherContactCompany(String contactCompany) {
        getConfig().put(OTHER_CONTACT_COMPANY, contactCompany);
    }

    public void setOtherContactPhone(String contactPhone) {
        getConfig().put(OTHER_CONTACT_PHONE, contactPhone);
    }

    public String getBillingContactEmail() {
        return getConfig().get(BILLING_CONTACT_EMAIL);
    }

    public String getBillingContactCompany() {
        return getConfig().get(BILLING_CONTACT_COMPANY);
    }

    public String getBillingContactPhone() {
        return getConfig().get(BILLING_CONTACT_PHONE);
    }

    public void setBillingContactEmail(String contactEmail) {
        getConfig().put(BILLING_CONTACT_EMAIL, contactEmail);
    }

    public void setBillingContactCompany(String contactCompany) {
        getConfig().put(BILLING_CONTACT_COMPANY, contactCompany);
    }
    
    public void setBillingContactPhone(String contactPhone) {
        getConfig().put(BILLING_CONTACT_PHONE, contactPhone);
    }

    public String getBillingContactRegistryName() {
        return getConfig().get(BILLING_CONTACT_REGISTRY_NAME);
    }

    public void setBillingContactRegistryName(String billingContactRegistryName) {
        getConfig().put(BILLING_CONTACT_REGISTRY_NAME, billingContactRegistryName);
    }

    public String getBillingContactSiteAddress() {
        return getConfig().get(BILLING_CONTACT_SITE_ADDRESS);
    }

    public void  setBillingContactSiteAddress(String billingContactSiteAddress) {
        getConfig().put(BILLING_CONTACT_SITE_ADDRESS, billingContactSiteAddress);
    }

    public String getBillingContactSiteNumber() {
        return getConfig().get(BILLING_CONTACT_SITE_NUMBER);
    }

    public void setBillingContactSiteNumber(String billingContactSiteNumber) {
        getConfig().put(BILLING_CONTACT_SITE_NUMBER, billingContactSiteNumber);
    }

    public String getBillingContactSiteZipCode() {
        return getConfig().get(BILLING_CONTACT_SITE_ZIP_CODE);
    }

    public void setBillingContactSiteZipCode(String billingContactSiteZipCode) {
        getConfig().put(BILLING_CONTACT_SITE_ZIP_CODE, billingContactSiteZipCode);
    }

    public String getBillingContactSiteProvince() {
        return getConfig().get(BILLING_CONTACT_SITE_PROVINCE);
    }

    public void setBillingContactSiteProvince(String billingContactSiteProvince) {
        getConfig().put(BILLING_CONTACT_SITE_PROVINCE, billingContactSiteProvince);
    }

    public String getBillingContactSiteCountry() {
        return getConfig().get(BILLING_CONTACT_SITE_COUNTRY);
    }

    public void setBillingContactSiteCountry(String billingContactSiteCountry) {
        getConfig().put(BILLING_CONTACT_SITE_COUNTRY, billingContactSiteCountry);
    }

    public String getBillingContactSiteCity() {
        return getConfig().get(BILLING_CONTACT_SITE_CITY);
    }

    public void setBillingContactSiteCity(String billingContactSiteCity) {
        getConfig().put(BILLING_CONTACT_SITE_CITY, billingContactSiteCity);
    }

    public boolean isDebugEnabled() {
        return Boolean.valueOf(getConfig().get(SPID_RESPONSE_DEBUG_ENABLED));
    }

    public void setDebugEnabled(boolean isDebugEnabled) {
        getConfig().put(SPID_RESPONSE_DEBUG_ENABLED, String.valueOf(isDebugEnabled));
    }

    public static List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
        .property()
        .name(ORGANIZATION_NAMES)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.organization-names")
        .helpText("identity-provider.spid.organization-names.tooltip")
        .add()

        .property()
        .name(IDP_ENTITY_ID)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.saml.idp-entity-id")
        .helpText("identity-provider.saml.idp-entity-id.tooltip")
        .add()

        .property()
        .name(ORGANIZATION_DISPLAY_NAMES)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.organization-display-names")
        .helpText("identity-provider.spid.organization-display-names.tooltip")
        .add()

        .property()
        .name(ORGANIZATION_URLS)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.organization-urls")
        .helpText("identity-provider.spid.organization-urls.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_SP_PRIVATE)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("identity-provider.spid.is-sp-private")
        .helpText("identity-provider.spid.is-sp-private.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_IPA_CODE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.ipaCode")
        .helpText("identity-provider.spid.ipaCode.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_VAT_NUMBER)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.vatNumber")
        .helpText("identity-provider.spid.vatNumber.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_FISCAL_CODE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.fiscalCode")
        .helpText("identity-provider.spid.fiscalCode.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_COMPANY)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactCompany.other")
        .helpText("identity-provider.spid.contactCompany.other.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_PHONE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactPhone.other")
        .helpText("identity-provider.spid.contactPhone.other.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_EMAIL)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactEmail.other")
        .helpText("identity-provider.spid.contactEmail.other.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_COMPANY)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactCompany.billing")
        .helpText("identity-provider.spid.contactCompany.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_PHONE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactPhone.billing")
        .helpText("identity-provider.spid.contactPhone.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_EMAIL)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactEmail.billing")
        .helpText("identity-provider.spid.contactEmail.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_REGISTRY_NAME)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.RegistryName.billing")
        .helpText("identity-provider.spid.RegistryName.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_SITE_ADDRESS)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.site.address.billing")
        .helpText("identity-provider.spid.site.address.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_SITE_NUMBER)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.site.number.billing")
        .helpText("identity-provider.spid.site.number.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_SITE_CITY)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.site.city.billing")
        .helpText("identity-provider.spid.site.city.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_SITE_ZIP_CODE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.site.zipCode.billing")
        .helpText("identity-provider.spid.site.zipCode.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_SITE_PROVINCE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.site.province.billing")
        .helpText("identity-provider.spid.site.province.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_SITE_COUNTRY)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.site.countryCode.billing")
        .helpText("identity-provider.spid.site.countryCode.billing.tooltip")
        .add()

        .property()
        .name(SPID_RESPONSE_DEBUG_ENABLED)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("identity-provider.spid.debug-enabled")
        .helpText("identity-provider.spid.debug-enabled.tooltip")
        .add()
        
        .build();
    }
    
}
