/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.keycloak.client.model;

import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * Client Registration information
 */
public class ClientInfo {

    @SerializedName("client_id")
    private String clientId;
    @SerializedName("client_secret")
    private String clientSecret;
    @SerializedName("client_name")
    private String clientName;
    @SerializedName("redirect_uris")
    private List<String> callBackUrls;
    @SerializedName("token_endpoint_auth_method")
    private String tokenEndpointAuthenticationMethod;
    @SerializedName("grant_types")
    private List<String> grantTypes;
    @SerializedName("response_types")
    private List<String> responseTypes;
    @SerializedName("subject_type")
    private String subjectType;
    @SerializedName("tls_client_certificate_bound_access_tokens")
    private boolean enableClientCertificateBindAccessToken;
    @SerializedName("client_secret_expires_at")
    private Long clientSecretExpiresAt;

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public String getClientSecret() {

        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {

        this.clientSecret = clientSecret;
    }

    public String getClientName() {

        return clientName;
    }

    public void setClientName(String clientName) {

        this.clientName = clientName;
    }

    public List<String> getCallBackUrls() {

        return callBackUrls;
    }

    public void setCallBackUrls(List<String> callBackUrls) {

        this.callBackUrls = callBackUrls;
    }

    public String getTokenEndpointAuthenticationMethod() {

        return tokenEndpointAuthenticationMethod;
    }

    public void setTokenEndpointAuthenticationMethod(String tokenEndpointAuthenticationMethod) {

        this.tokenEndpointAuthenticationMethod = tokenEndpointAuthenticationMethod;
    }

    public List<String> getGrantTypes() {

        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {

        this.grantTypes = grantTypes;
    }

    public List<String> getResponseTypes() {

        return responseTypes;
    }

    public void setResponseTypes(List<String> responseTypes) {

        this.responseTypes = responseTypes;
    }

    public String getSubjectType() {

        return subjectType;
    }

    public void setSubjectType(String subjectType) {

        this.subjectType = subjectType;
    }

    public boolean isEnableClientCertificateBindAccessToken() {

        return enableClientCertificateBindAccessToken;
    }

    public void setEnableClientCertificateBindAccessToken(boolean enableClientCertificateBindAccessToken) {

        this.enableClientCertificateBindAccessToken = enableClientCertificateBindAccessToken;
    }

    public Long getClientSecretExpiresAt() {

        return clientSecretExpiresAt;
    }

    public void setClientSecretExpiresAt(Long clientSecretExpiresAt) {

        this.clientSecretExpiresAt = clientSecretExpiresAt;
    }
}
