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

import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class SpidIdentityProviderConfig extends SAMLIdentityProviderConfig  {

    public static final String ORGANIZATION_NAMES = "organizationNames";
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
    public static final String ENTITY_ID_IDP = "entityIdIdp";

    public SpidIdentityProviderConfig(){
    }

    public SpidIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
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

    public String getEntityIdIdp() {
        return getConfig().get(ENTITY_ID_IDP);
    }

    public void setEntityIdIdp(String entityIdIdp) {
        getConfig().put(ENTITY_ID_IDP, entityIdIdp);
    }
    
}
