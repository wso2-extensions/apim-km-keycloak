/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.keycloak.client;

import java.time.LocalDateTime;

/**
 * Created to store the access token information to re use non expired access tokens to invoke
 * admin REST services
 */
public class KeycloakTokenInfo {

    private String accessToken;
    private String refreshToken;
    private long validityPeriod;
    private LocalDateTime expiry;
    private LocalDateTime refreshExpiry;

    /**
     * Constructor to create an object of the type KeycloakTokenInfo with the the following paramters
     * @param accessToken
     * @param refreshToken
     * @param expiresIn
     * @param refreshExpiresIn
     */
    public KeycloakTokenInfo(String accessToken, String refreshToken, long expiresIn, long refreshExpiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.validityPeriod = expiresIn;
        expiry = LocalDateTime.now().plusSeconds(expiresIn);
        refreshExpiry = LocalDateTime.now().plusSeconds(refreshExpiresIn);
    }

    /**
     * Getter method to retrieve the accessToken from KeycloakTokenInfo
     * @return accessToken
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Getter method to retrieve the accessToken from KeycloakTokenInfo
     * @return refreshToken
     */
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     * Method to check the accessToken is valid or expired
     * @return boolean whether the access token is expired or not.
     */
    public boolean isValid(){
        return expiry.isAfter(LocalDateTime.now());
    }

    /**
     * Method to check the refresh token is valid or expired
     * @return boolean whether the refresh token is expired or not.
     */
    public boolean isRefreshValid(){
        return refreshExpiry.isAfter(LocalDateTime.now());
    }

    /**
     * Method to check the refresh token is valid or expired
     * @return
     */
    public void invalidateRefresh() {
        refreshExpiry = LocalDateTime.now().minusHours(24);
    }

    /**
     * Getter method to retrieve the accessToken from KeycloakTokenInfo
     * @return validityPeriod
     */
    public long getValidityPeriod() {
        return validityPeriod;
    }

    /**
     * Getter method to retrieve the accessToken from KeycloakTokenInfo
     * @return expiry
     */
    public LocalDateTime getExpiryTime() {
        return expiry;
    }

    /**
     * Getter method to retrieve the accessToken from KeycloakTokenInfo
     * @return refreshExpiry
     */
    public LocalDateTime getRefreshExpiryTime() {
        return refreshExpiry;
    }
}
