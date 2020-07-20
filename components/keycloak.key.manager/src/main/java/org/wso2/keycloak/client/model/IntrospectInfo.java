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

/**
 * Introspection info related to introspect endpoint.
 */
public class IntrospectInfo {

    @SerializedName("exp")
    private long expiryTime;
    @SerializedName("iat")
    private long issuedAt;
    @SerializedName("jti")
    private String jti;
    @SerializedName("iss")
    private String issuer;
    @SerializedName("aud")
    private String audience;
    @SerializedName("sub")
    private String subject;
    @SerializedName("typ")
    private String tokenType;
    @SerializedName("azp")
    private String consumerKey;
    @SerializedName("session_state")
    private String sessionState;
    @SerializedName("preferred_username")
    private String preferredUsername;
    @SerializedName("email_verified")
    private boolean isEmailVerified;
    @SerializedName("acr")
    private String acr;
    @SerializedName("scope")
    private String scope;
    @SerializedName("client_id")
    private String clientId;
    @SerializedName("username")
    private String username;
    @SerializedName("active")
    private boolean active;

    public long getExpiryTime() {

        return expiryTime;
    }

    public void setExpiryTime(long expiryTime) {

        this.expiryTime = expiryTime;
    }

    public long getIssuedAt() {

        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {

        this.issuedAt = issuedAt;
    }

    public String getJti() {

        return jti;
    }

    public void setJti(String jti) {

        this.jti = jti;
    }

    public String getIssuer() {

        return issuer;
    }

    public void setIssuer(String issuer) {

        this.issuer = issuer;
    }

    public String getAudience() {

        return audience;
    }

    public void setAudience(String audience) {

        this.audience = audience;
    }

    public String getSubject() {

        return subject;
    }

    public void setSubject(String subject) {

        this.subject = subject;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setTokenType(String tokenType) {

        this.tokenType = tokenType;
    }

    public String getConsumerKey() {

        return consumerKey;
    }

    public void setConsumerKey(String consumerKey) {

        this.consumerKey = consumerKey;
    }

    public String getSessionState() {

        return sessionState;
    }

    public void setSessionState(String sessionState) {

        this.sessionState = sessionState;
    }

    public String getPreferredUsername() {

        return preferredUsername;
    }

    public void setPreferredUsername(String preferredUsername) {

        this.preferredUsername = preferredUsername;
    }

    public boolean isEmailVerified() {

        return isEmailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {

        isEmailVerified = emailVerified;
    }

    public String getAcr() {

        return acr;
    }

    public void setAcr(String acr) {

        this.acr = acr;
    }

    public String getScope() {

        return scope;
    }

    public void setScope(String scope) {

        this.scope = scope;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public String getUsername() {

        return username;
    }

    public void setUsername(String username) {

        this.username = username;
    }

    public boolean isActive() {

        return active;
    }

    public void setActive(boolean active) {

        this.active = active;
    }
}
