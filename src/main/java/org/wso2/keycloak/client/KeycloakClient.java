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

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.*;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.*;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

/**
 * This class provides the implementation to use "Keycloak" for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class KeycloakClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(KeycloakClient.class);
    private KeyManagerConfiguration configuration;
    private KeycloakTokenInfo keycloakTokenInfo;

    /**
     * {@code APIManagerComponent} calls this method, passing KeyManagerConfiguration as a {@code String}.
     *
     * @param keyManagerConfiguration Configuration as a {@link KeyManagerConfiguration}
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        this.configuration = keyManagerConfiguration;
    }

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        String clientName = oAuthApplicationInfo.getClientName();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating an OAuth client in Keycloak authorization server with application name %s",
                    clientName));
        }
        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.
                OAUTH_CLIENT_USERNAME);
        String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);
        if (keyType != null) {
            clientName = userId + "_" + clientName + "_" + keyType;
        }
        oAuthApplicationInfo.setClientId(clientName);
        oAuthApplicationInfo.setClientName(clientName);
        String keyCloakInstanceUrl = configuration.getParameter(KeycloakConstants.KEYCLOAK_INSTANCE_URL);
        String keycloakRealm = configuration.getParameter(KeycloakConstants.KEYCLOAK_REALM_NAME);
        String registrationEndpoint = keyCloakInstanceUrl + KeycloakConstants.KEYCLOAK_ADMIN_CONTEXT + keycloakRealm +
                KeycloakConstants.CLIENT_ENDPOINT;
        String[] scope = ((String) oAuthApplicationInfo.getParameter(KeycloakConstants.TOKEN_SCOPE)).split(",");
        Object tokenGrantType = oAuthApplicationInfo.getParameter(KeycloakConstants.TOKEN_GRANT_TYPE);
        Map<String, Object> paramMap = new HashMap<String, Object>();
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build();) {
            // Create the JSON Payload that should be sent to OAuth Server.
            String jsonPayload = createJsonPayloadFromOauthApplication(oAuthApplicationInfo, paramMap);
            String accessToken = getAccessToken();
            if (log.isDebugEnabled()) {
                log.debug(String.format("Payload to create a new client : %s for the application %s", jsonPayload,
                        clientName));
            }
            HttpPost httpPost = new HttpPost(registrationEndpoint);
            httpPost.setEntity(new StringEntity(jsonPayload, KeycloakConstants.UTF_8));
            httpPost.setHeader(KeycloakConstants.HTTP_HEADER_CONTENT_TYPE, KeycloakConstants.APPLICATION_JSON);
            httpPost.setHeader(KeycloakConstants.AUTHORIZATION, KeycloakConstants.AUTHENTICATION_BEARER + accessToken);

            if (log.isDebugEnabled()) {
                log.debug(String.format("Invoking HTTP request to create new client in Keycloak for the application %s",
                        clientName));
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();

            // If successful a 201 will be returned with no body
            if (HttpStatus.SC_CREATED == statusCode) {
                String clientSecret = getClientSecret(clientName);
                JSONObject clientInfoJsonObject = getClientById(clientName);
                oAuthApplicationInfo = createOAuthAppInfoFromResponse(clientInfoJsonObject);
                oAuthApplicationInfo.addParameter(KeycloakConstants.TOKEN_SCOPE, scope);
                oAuthApplicationInfo.addParameter(KeycloakConstants.TOKEN_GRANT_TYPE, tokenGrantType);
                oAuthApplicationInfo.addParameter(KeycloakConstants.CLIENT_SECRET, clientSecret);
                oAuthApplicationInfo.setClientSecret(clientSecret);
                return oAuthApplicationInfo;
            } else {
                handleException(String.format("Error occured while registering the new client in Keycloak. " +
                        "Response : %s", statusCode));
            }
        } catch (UnsupportedEncodingException e) {
            handleException(KeycloakConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        } catch (IOException e) {
            handleException("Error while reading response body", e);
        }
        return null;
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        // We have to send the client id with the update request.
        String clientId = oAuthApplicationInfo.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Updating an OAuth client in Keycloak authorization server for the Consumer Key %s",
                    clientId));
        }
        // Getting Client Instance Url and API Key from Config.
        String keyCloakInstanceUrl = configuration.getParameter(KeycloakConstants.KEYCLOAK_INSTANCE_URL);
        String keycloakRealm = configuration.getParameter(KeycloakConstants.KEYCLOAK_REALM_NAME);
        String registrationEndpoint = keyCloakInstanceUrl + KeycloakConstants.KEYCLOAK_ADMIN_CONTEXT + keycloakRealm +
                KeycloakConstants.CLIENT_ENDPOINT + clientId;

        Map<String, Object> paramMap = new HashMap<String, Object>();
        if (StringUtils.isNotEmpty(clientId)) {
            paramMap.put(KeycloakConstants.KEYCLOAK_CLIENT_ID, clientId);
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build();) {
            // Create the JSON Payload that should be sent to OAuth Server.
            String jsonPayload = createJsonPayloadFromOauthApplication(oAuthApplicationInfo, paramMap);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Payload to update an OAuth client : %s for the Consumer Key %s", jsonPayload,
                        clientId));
            }
            HttpPut httpPut = new HttpPut(registrationEndpoint);
            httpPut.setEntity(new StringEntity(jsonPayload, KeycloakConstants.UTF_8));
            httpPut.setHeader(KeycloakConstants.HTTP_HEADER_CONTENT_TYPE, KeycloakConstants.APPLICATION_JSON);
            String accessToken = getAccessToken();
            httpPut.setHeader(KeycloakConstants.AUTHORIZATION, KeycloakConstants.AUTHENTICATION_BEARER + accessToken);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invoking HTTP request to update client in Keycloak for Consumer Key %s", clientId));
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_NO_CONTENT){
                String clientSecret = getClientSecret(clientId);
                JSONObject clientInfoJsonObject = getClientById(clientId);
                oAuthApplicationInfo = createOAuthAppInfoFromResponse(clientInfoJsonObject);
                oAuthApplicationInfo.addParameter(KeycloakConstants.CLIENT_SECRET, clientSecret);
                oAuthApplicationInfo.setClientSecret(clientSecret);
                return oAuthApplicationInfo;
            } else {
                handleException(String.format("Error occured when updating the Client with Consumer Key %s" +
                        " : Response: %s", clientId, statusCode));
            }
        } catch (UnsupportedEncodingException e) {
            handleException(KeycloakConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        }
        return null;
    }

    @Override
    public void deleteApplication(String clientId) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Deleting an OAuth client in Keycloak authorization server for the Consumer Key: %s",
                    clientId));
        }
        // Getting Client Instance Url and API Key from Config.
        String keyCloakInstanceUrl = configuration.getParameter(KeycloakConstants.KEYCLOAK_INSTANCE_URL);
        String keycloakRealm = configuration.getParameter(KeycloakConstants.KEYCLOAK_REALM_NAME);
        String registrationEndpoint = keyCloakInstanceUrl + KeycloakConstants.KEYCLOAK_ADMIN_CONTEXT + keycloakRealm +
                KeycloakConstants.CLIENT_ENDPOINT + clientId;

        String accessToken = getAccessToken();
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build();) {
            HttpDelete httpDelete = new HttpDelete(registrationEndpoint);
            httpDelete.addHeader(KeycloakConstants.AUTHORIZATION, KeycloakConstants.AUTHENTICATION_BEARER + accessToken);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invoking HTTP request to delete the client for the Consumer Key %s", clientId));
            }
            HttpResponse response = httpClient.execute(httpDelete);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_NO_CONTENT) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("OAuth Client for the Consumer Key %s has been successfully deleted",
                            clientId));
                }
            } else {
                handleException(String.format("Problem occurred while deleting client for the Consumer Key %s." +
                        " Response : %s", clientId, statusCode));
            }
        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        }
    }

    @Override
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo;
        String clientSecret = getClientSecret(clientId);
        JSONObject clientInfoJsonObject = getClientById(clientId);
        oAuthApplicationInfo = createOAuthAppInfoFromResponse(clientInfoJsonObject);
        oAuthApplicationInfo.setClientSecret(clientSecret);
        return oAuthApplicationInfo;
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest) throws APIManagementException {
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        String clientId = accessTokenRequest.getClientId();
        String clientSecret = accessTokenRequest.getClientSecret();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Get new client access token from authorization server for the Consumer Key %s",
                    clientId));
        }
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        Object grantType = accessTokenRequest.getGrantType();
        if (grantType == null) {
            grantType = KeycloakConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
        }
        parameters.add(new BasicNameValuePair(KeycloakConstants.GRANT_TYPE, (String) grantType));
        String scopeString = convertToString(accessTokenRequest.getScope());
        if (!StringUtils.isEmpty(scopeString)) {
            parameters.add(new BasicNameValuePair(KeycloakConstants.ACCESS_TOKEN_SCOPE, scopeString));
        }
        parameters.add(new BasicNameValuePair(KeycloakConstants.CLIENT_ID, clientId));
        parameters.add(new BasicNameValuePair(KeycloakConstants.CLIENT_SECRET, clientSecret));

        JSONObject responseJSON = getAccessTokenWithParameters(parameters);
        if (responseJSON != null) {
            updateTokenInfo(tokenInfo, responseJSON);
            if (log.isDebugEnabled()) {
                log.debug(String.format("OAuth token has been successfully validated for the Consumer Key %s",
                        clientId));
            }
            return tokenInfo;
        } else {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            if (log.isDebugEnabled()) {
                log.debug(String.format("OAuth token validation failed for the Consumer Key %s", clientId));
            }
        }

        return tokenInfo;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting access token metadata from authorization server. Access token %s",
                    accessToken));
        }
        String clientId = null;
        try {
            SignedJWT parsedJWTToken = (SignedJWT) JWTParser.parse(accessToken);
            clientId = (String) parsedJWTToken.getJWTClaimsSet().getClaim(KeycloakConstants.JWT_AZP_CLAIM);
        } catch (java.text.ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid JWT token. Token: " + accessToken);
            }
            handleException("Invalid JWT token. Failed to decode the token.");
        }
        String clientSecret = getClientSecret(clientId);
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        String keyCloakInstanceUrl = configuration.getParameter(KeycloakConstants.KEYCLOAK_INSTANCE_URL);
        String keycloakRealm = configuration.getParameter(KeycloakConstants.KEYCLOAK_REALM_NAME);
        String introspectEndpoint = keyCloakInstanceUrl + KeycloakConstants.KEYCLOAK_TOKEN_CONTEXT + keycloakRealm +
                KeycloakConstants.KEYCLOAK_INTROSPECT_PATH;
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build();) {
            List<NameValuePair> parameters = new ArrayList<NameValuePair>();
            parameters.add(new BasicNameValuePair(KeycloakConstants.TOKEN, accessToken));
            parameters.add(new BasicNameValuePair(KeycloakConstants.CLIENT_ID, clientId));
            parameters.add(new BasicNameValuePair(KeycloakConstants.CLIENT_SECRET, clientSecret));
            HttpPost httpPost = new HttpPost(introspectEndpoint);
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            JSONObject responseJSON = null;

            if (HttpStatus.SC_OK == statusCode) {
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    handleException(String.format(KeycloakConstants.STRING_FORMAT,
                            KeycloakConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
                }

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeycloakConstants.UTF_8));) {
                    responseJSON = getParsedObjectByReader(reader);
                }
                if (responseJSON == null) {
                    log.error(String.format("Invalid token %s", accessToken));
                    tokenInfo.setTokenValid(false);
                    tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                    return tokenInfo;
                }
                tokenInfo.setTokenValid((Boolean) responseJSON.get(KeycloakConstants.ACCESS_TOKEN_ACTIVE));

                if (tokenInfo.isTokenValid()) {
                    long expiryTime = (Long) responseJSON.get(KeycloakConstants.ACCESS_TOKEN_EXPIRY) * 1000;
                    long issuedTime = (Long) responseJSON.get(KeycloakConstants.ACCESS_TOKEN_ISSUED) * 1000;
                    tokenInfo.setValidityPeriod(expiryTime - issuedTime);

                    String tokScopes = (String) responseJSON.get(KeycloakConstants.ACCESS_TOKEN_SCOPE);

                    if (StringUtils.isNotEmpty(tokScopes)) {
                        tokenInfo.setScope(tokScopes.split("\\s+"));
                    }

                    tokenInfo.setIssuedTime(issuedTime);
                    tokenInfo.setConsumerKey((String) responseJSON.get(KeycloakConstants.CLIENT_ID));
                    tokenInfo.setEndUserName(responseJSON.get(KeycloakConstants.ACCESS_TOKEN_USER_NAME)+"@"+
                            MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                    tokenInfo.addParameter(KeycloakConstants.ACCESS_TOKEN_SUBJECT,
                            responseJSON.get(KeycloakConstants.ACCESS_TOKEN_SUBJECT));
                    tokenInfo.addParameter(KeycloakConstants.ACCESS_TOKEN_AUDIENCE,
                            responseJSON.get(KeycloakConstants.ACCESS_TOKEN_AUDIENCE));
                    tokenInfo.addParameter(KeycloakConstants.ACCESS_TOKEN_ISSUER,
                            responseJSON.get(KeycloakConstants.ACCESS_TOKEN_ISSUER));
                    tokenInfo.addParameter(KeycloakConstants.ACCESS_TOKEN_TYPE,
                            responseJSON.get(KeycloakConstants.ACCESS_TOKEN_TYPE));
                    tokenInfo.addParameter(KeycloakConstants.ACCESS_TOKEN_USER_ID,
                            responseJSON.get(KeycloakConstants.ACCESS_TOKEN_USER_ID));
                    tokenInfo.addParameter(KeycloakConstants.ACCESS_TOKEN_IDENTIFIER,
                            responseJSON.get(KeycloakConstants.ACCESS_TOKEN_IDENTIFIER));

                    return tokenInfo;
                }
            } else {
                log.error(String.format("Invalid token %s", accessToken));
                tokenInfo.setTokenValid(false);
                tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                return tokenInfo;
            }
        } catch (ParseException e) {
            handleException(KeycloakConstants.ERROR_WHILE_PARSE_RESPONSE, e);
        } catch (UnsupportedEncodingException e) {
            handleException(KeycloakConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request to OAuth provider. ", e);
        } catch (IOException e) {
            handleException(KeycloakConstants.ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER, e);
        }

        return null;
    }

    /**
     * This is used to build accesstoken request from OAuth application info.
     *
     * @param oAuthApplication OAuth application details.
     * @param tokenRequest     AccessTokenRequest that is need to be updated with addtional info.
     * @return AccessTokenRequest after adding OAuth application details.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(
            OAuthApplicationInfo oAuthApplication, AccessTokenRequest tokenRequest) throws APIManagementException {
        if (oAuthApplication == null) {
            return tokenRequest;
        }
        if (tokenRequest == null) {
            tokenRequest = new AccessTokenRequest();
        }
        String clientName = oAuthApplication.getClientName();
        if (oAuthApplication.getClientId() == null) {
            throw new APIManagementException(String.format("Consumer key is missing for the Application: %s",
                    clientName));
        }
        if(oAuthApplication.getClientSecret() == null) {
            log.error(String.format("Consumer Secret is missing for the Application: %s", clientName));
        }
        tokenRequest.setClientId(oAuthApplication.getClientId());
        tokenRequest.setClientSecret(oAuthApplication.getClientSecret());

        if (oAuthApplication.getParameter(KeycloakConstants.TOKEN_SCOPE) != null) {
            String[] tokenScopes = null;
            if (oAuthApplication.getParameter(KeycloakConstants.TOKEN_SCOPE) instanceof String[]) {
                tokenScopes = (String[]) oAuthApplication.getParameter(KeycloakConstants.TOKEN_SCOPE);
            }
            if (oAuthApplication.getParameter(KeycloakConstants.TOKEN_SCOPE) instanceof String) {
                tokenScopes = oAuthApplication.getParameter(KeycloakConstants.TOKEN_SCOPE).toString().split(",");
            }
            tokenRequest.setScope(tokenScopes);
            oAuthApplication.addParameter(KeycloakConstants.TOKEN_SCOPE, Arrays.toString(tokenScopes));
        }
        if (oAuthApplication.getParameter(ApplicationConstants.VALIDITY_PERIOD) != null) {
            tokenRequest.setValidityPeriod(Long.parseLong((String) oAuthApplication.getParameter(ApplicationConstants
                    .VALIDITY_PERIOD)));
        }
        Object grantType = oAuthApplication.getParameter(KeycloakConstants.TOKEN_GRANT_TYPE);
        if (grantType != null) {
            tokenRequest.setGrantType((String) grantType);
        }

        return tokenRequest;
    }

    /**
     * Returns the key manager configuration of the current API Manager instance
     * @return configuration
     * @throws APIManagementException
     */
    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {
        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with Application in API Manager
     *
     * @param oAuthAppRequest Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        return oAuthAppRequest.getOAuthApplicationInfo();
    }

    @Override
    public boolean registerNewResource(API api, Map map) throws APIManagementException {
        return true;
    }

    @Override
    public Map getResourceByApiId(String s) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map map) throws APIManagementException {
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String s) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return Collections.emptySet();
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    /**
     * This method will create {@code OAuthApplicationInfo} object from a Map of Attributes.
     *
     * @param responseMap Response returned from server as a Map
     * @return OAuthApplicationInfo object will return.
     */
    private OAuthApplicationInfo createOAuthAppInfoFromResponse(JSONObject responseMap) {
        OAuthApplicationInfo result = new OAuthApplicationInfo();
        result.setClientId((String)responseMap.get(KeycloakConstants.KEYCLOAK_CLIENT_ID));
        result.setClientName((String)responseMap.get(KeycloakConstants.KEYCLOAK_CLIENT_ID));
        ArrayList<String> uris = new ArrayList<>();
        Iterator i = ((JSONArray)responseMap.get(KeycloakConstants.CLIENT_REDIRECT_URIS)).iterator();
        while(i.hasNext()){
            uris.add((String)i.next());
        }
        String joinedUris = StringUtils.join(uris, ",");
        String escapedUris = escapeHtml(joinedUris);
        result.setCallBackURL(joinedUris);
        result.setClientSecret((String)responseMap.get(KeycloakConstants.CLIENT_SECRET));
        result.setIsSaasApplication(false);
        ArrayList<String> grantTypeList = new ArrayList<>();

        if ((Boolean) responseMap.get(KeycloakConstants.GRANT_TYPE_IMPLICIT_KEYCLOAK)) {
            grantTypeList.add(KeycloakConstants.GRANT_TYPE_IMPLICIT);
        }
        if ((Boolean) responseMap.get(KeycloakConstants.GRANT_TYPE_AUTHORIZATION_CODE_KEYCLOAK)) {
            grantTypeList.add(KeycloakConstants.GRANT_TYPE_AUTHORIZATION_CODE);
        }
        if ((Boolean) responseMap.get(KeycloakConstants.GRANT_TYPE_CLIENT_CREDENTIALS_KEYCLOAK)) {
            grantTypeList.add(KeycloakConstants.GRANT_TYPE_CLIENT_CREDENTIALS);
        }
        if ((Boolean) responseMap.get(KeycloakConstants.GRANT_TYPE_PASSWORD_KEYCLOAK)) {
            grantTypeList.add(KeycloakConstants.GRANT_TYPE_PASSWORD);
        }

        result.addParameter(KeycloakConstants.CLIENT_GRANT_TYPES, StringUtils.join(grantTypeList, " "));
        result.addParameter(KeycloakConstants.CALLBACK_URL, escapedUris);
        result.addParameter(KeycloakConstants.REDIRECT_URIS, escapedUris);

        return result;
    }


    /**
     * This method can be used to create a JSON Payload out of the Parameters defined in an OAuth Application
     * in order to create and update the client.
     *
     * @param oAuthApplicationInfo Object that needs to be converted.
     * @param paramMap             It has additional parameters to create the Json payload.
     * @return JSON payload.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private String createJsonPayloadFromOauthApplication(OAuthApplicationInfo oAuthApplicationInfo,
                                                         Map<String, Object> paramMap) throws APIManagementException {
        String clientId = oAuthApplicationInfo.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating json payload from Oauth application info for the application: %s",
                    clientId));
        }

        if (StringUtils.isNotEmpty(clientId)) {
            paramMap.put(KeycloakConstants.KEYCLOAK_CLIENT_ID, clientId);
            paramMap.put(KeycloakConstants.KEYCLOAK_ID, clientId);
        }

        String clientRedirectUri = oAuthApplicationInfo.getCallBackURL();
        if (!StringUtils.isNotEmpty(clientRedirectUri)) {
            List<String> redirectUris = Collections.singletonList(clientRedirectUri);
            paramMap.put(KeycloakConstants.CLIENT_REDIRECT_URIS, redirectUris);
        }
        
        Object clientGrantTypes = oAuthApplicationInfo.getParameter(KeycloakConstants.CLIENT_GRANT_TYPES);
        if (clientGrantTypes != null) {
            List<String> grantTypes = Arrays.asList(((String) clientGrantTypes).split(","));
            if (grantTypes.contains(KeycloakConstants.GRANT_TYPE_CLIENT_CREDENTIALS)) {
                paramMap.put(KeycloakConstants.GRANT_TYPE_CLIENT_CREDENTIALS_KEYCLOAK, true);
            } else {
                paramMap.put(KeycloakConstants.GRANT_TYPE_CLIENT_CREDENTIALS_KEYCLOAK, false);
            }
            if (grantTypes.contains(KeycloakConstants.GRANT_TYPE_AUTHORIZATION_CODE)) {
                paramMap.put(KeycloakConstants.GRANT_TYPE_AUTHORIZATION_CODE_KEYCLOAK, true);
            } else {
                paramMap.put(KeycloakConstants.GRANT_TYPE_AUTHORIZATION_CODE_KEYCLOAK, false);
            }
            if (grantTypes.contains(KeycloakConstants.GRANT_TYPE_IMPLICIT)) {
                paramMap.put(KeycloakConstants.GRANT_TYPE_IMPLICIT_KEYCLOAK, true);
            } else {
                paramMap.put(KeycloakConstants.GRANT_TYPE_IMPLICIT_KEYCLOAK, false);
            }
            if (grantTypes.contains(KeycloakConstants.GRANT_TYPE_PASSWORD)) {
                paramMap.put(KeycloakConstants.GRANT_TYPE_PASSWORD_KEYCLOAK, true);
            } else {
                paramMap.put(KeycloakConstants.GRANT_TYPE_PASSWORD_KEYCLOAK, false);
            }
        }
        return JSONObject.toJSONString(paramMap);
    }

    /**
     * Returns a space separate string from list of the contents in the string array.
     *
     * @param stringArray an array of strings.
     * @return space separated string.
     */
    private static String convertToString(String[] stringArray) {
        if (stringArray != null) {
            StringBuilder sb = new StringBuilder();
            List<String> strList = Arrays.asList(stringArray);
            for (String s : strList) {
                sb.append(s);
                sb.append(" ");
            }
            return sb.toString().trim();
        }

        return null;
    }

    /**
     * Can be used to parse {@code BufferedReader} object that are taken from response stream, to a {@code JSONObject}.
     *
     * @param reader {@code BufferedReader} object from response.
     * @return JSON payload as a name value map.
     */
    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {
        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);
        }
        return parsedObject;
    }

    /**
     * Returns base64 encoded credentaials.
     *
     * @param clientId     clientId of the oauth client.
     * @param clientSecret clientSecret of the oauth clients.
     * @return String base64 encode string.
     */
    private static String getEncodedCredentials(String clientId, String clientSecret) throws APIManagementException {
        String encodedCredentials;
        try {
            encodedCredentials = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret)
                    .getBytes(KeycloakConstants.UTF_8));
        } catch (UnsupportedEncodingException e) {
            throw new APIManagementException(KeycloakConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        }

        return encodedCredentials;
    }


    /**
     * Common method to throw exceptions. This will only expect one parameter.
     *
     * @param msg error message as a string.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private static void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * Common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws APIManagementException This is the custom exception class for API management
     */
    private static void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    /**
     * Common method to get an access token in order to invoke an admin REST service in Keycloak.
     * If a valid one already available method will return it. Else it will try refresh token to generate a new one.
     * @return access_token Access token value
     * @throws APIManagementException This is the custom exception class for API management
     */
    private String getAccessToken() throws APIManagementException {
        if (keycloakTokenInfo != null && keycloakTokenInfo.isValid()) {
           return keycloakTokenInfo.getAccessToken();
        }
        String keycloakInstanceUrl = configuration.getParameter(KeycloakConstants.KEYCLOAK_INSTANCE_URL);
        String username = configuration.getParameter(KeycloakConstants.USERNAME);
        String password = configuration.getParameter(KeycloakConstants.PASSWORD);
        String client_id = configuration.getParameter(KeycloakConstants.CLIENT_ID);
        String keycloakRealm = configuration.getParameter(KeycloakConstants.KEYCLOAK_REALM_NAME);
        String keyCloakTokenEndpoint = keycloakInstanceUrl + KeycloakConstants.KEYCLOAK_TOKEN_CONTEXT + keycloakRealm +
                KeycloakConstants.KEYCLOAK_TOKEN_PATH;

        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build();) {
            List<NameValuePair> parameters = new ArrayList<NameValuePair>();
            parameters.add(new BasicNameValuePair(KeycloakConstants.USERNAME, username));
            parameters.add(new BasicNameValuePair(KeycloakConstants.PASSWORD, password));
            parameters.add(new BasicNameValuePair(KeycloakConstants.CLIENT_ID, client_id));
            if(keycloakTokenInfo != null && keycloakTokenInfo.isRefreshValid()){
                parameters.add(new BasicNameValuePair(KeycloakConstants.GRANT_TYPE,
                        KeycloakConstants.GRANT_TYPE_REFRESH_TOKEN));
                parameters.add(new BasicNameValuePair(KeycloakConstants.GRANT_TYPE_REFRESH_TOKEN,
                        keycloakTokenInfo.getRefreshToken()));
            } else {
                parameters.add(new BasicNameValuePair(KeycloakConstants.GRANT_TYPE, KeycloakConstants.GRANT_TYPE_PASSWORD));
            }
            HttpPost httpPost = new HttpPost(keyCloakTokenEndpoint);
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));
            httpPost.setHeader(KeycloakConstants.HTTP_HEADER_CONTENT_TYPE, KeycloakConstants.APPLICATION_URL_ENCODED);
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            if (HttpStatus.SC_OK == statusCode) {
                HttpEntity entity = response.getEntity();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeycloakConstants.UTF_8));) {
                    JSONObject responseJSON = getParsedObjectByReader(reader);
                    keycloakTokenInfo = new KeycloakTokenInfo((String) responseJSON.get(KeycloakConstants.ACCESS_TOKEN),
                            (String) responseJSON.get(KeycloakConstants.REFRESH_TOKEN),
                            (long) responseJSON.get(KeycloakConstants.ACCESS_TOKEN_EXPIRES_IN),
                            (long) responseJSON.get(KeycloakConstants.REFRESH_TOKEN_EXPIRES_IN));
                    return (String) responseJSON.get(KeycloakConstants.ACCESS_TOKEN);
                }
            }else if(keycloakTokenInfo != null && keycloakTokenInfo.isRefreshValid()){
                keycloakTokenInfo.invalidateRefresh();
                getAccessToken();
            }else{
                handleException("Error occurred while generating access token");
            }

        } catch (ParseException e) {
            handleException(KeycloakConstants.ERROR_WHILE_PARSE_RESPONSE, e);
        } catch (UnsupportedEncodingException e) {
            handleException(KeycloakConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request to OAuth provider. ", e);
        } catch (IOException e) {
            handleException(KeycloakConstants.ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER, e);
        }
        return null;
    }

    /**
     * Common method to get an access token using a set of parameters in order to initiate a valid oauth flow.
     * A list of parameters needed to generate a token for a certain grant_type has to be provided.
     * @param parameters A list of parameters such as username, password, client_id, client_secret, grant_type
     * @return Access token response
     * @throws APIManagementException This is the custom exception class for API management
     */
    private JSONObject getAccessTokenWithParameters(List<NameValuePair> parameters) throws APIManagementException {
        String keycloakInstanceUrl = configuration.getParameter(KeycloakConstants.KEYCLOAK_INSTANCE_URL);
        String keycloakRealm = configuration.getParameter(KeycloakConstants.KEYCLOAK_REALM_NAME);
        String keyCloakTokenEndpoint = keycloakInstanceUrl + KeycloakConstants.KEYCLOAK_TOKEN_CONTEXT + keycloakRealm +
                KeycloakConstants.KEYCLOAK_TOKEN_PATH;
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build();) {
            HttpPost httpPost = new HttpPost(keyCloakTokenEndpoint);
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));
            httpPost.setHeader(KeycloakConstants.HTTP_HEADER_CONTENT_TYPE, KeycloakConstants.APPLICATION_URL_ENCODED);
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            if (HttpStatus.SC_OK == statusCode) {
                HttpEntity entity = response.getEntity();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeycloakConstants.UTF_8));) {
                    JSONObject responseJSON = getParsedObjectByReader(reader);
                    return responseJSON;
                }
            }else{
                handleException("Error occurred while generating access token");
            }

        } catch (ParseException e) {
            handleException(KeycloakConstants.ERROR_WHILE_PARSE_RESPONSE, e);
        } catch (UnsupportedEncodingException e) {
            handleException(KeycloakConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request to OAuth provider. ", e);
        } catch (IOException e) {
            handleException(KeycloakConstants.ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER, e);
        }
        return null;
    }

    /**
     * This method returns the clientSecret related of a client with the given clientId in Keycloak
     * @param clientId Client id of a client in Keycloak
     * @return clientSecret belonging to the client with the given clientID In Keycloak
     * @throws APIManagementException This is the custom exception class for API management
     */
    private String getClientSecret(String clientId) throws APIManagementException{
        String accessToken = getAccessToken();
        String keyCloakInstanceUrl = configuration.getParameter(KeycloakConstants.KEYCLOAK_INSTANCE_URL);
        String keycloakRealm = configuration.getParameter(KeycloakConstants.KEYCLOAK_REALM_NAME);
        String clientSecretEndpoint = keyCloakInstanceUrl + KeycloakConstants.KEYCLOAK_ADMIN_CONTEXT + keycloakRealm +
                KeycloakConstants.CLIENT_ENDPOINT + clientId + KeycloakConstants.KEYCLOAK_CLIENT_SECRET_PATH;
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build();) {
            HttpGet httpGet = new HttpGet(clientSecretEndpoint);
            httpGet.setHeader(KeycloakConstants.AUTHORIZATION, KeycloakConstants.AUTHENTICATION_BEARER + accessToken);
            HttpResponse response = httpClient.execute(httpGet);
            int statusCode = response.getStatusLine().getStatusCode();
            if (HttpStatus.SC_OK == statusCode) {
                HttpEntity entity = response.getEntity();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeycloakConstants.UTF_8));) {
                    JSONObject responseJSON = getParsedObjectByReader(reader);
                    return (String) responseJSON.get(KeycloakConstants.CLIENT_SECRET_VALUE);
                }
            }
        } catch (ParseException e) {
            handleException(KeycloakConstants.ERROR_WHILE_PARSE_RESPONSE, e);
        } catch (UnsupportedEncodingException e) {
            handleException(KeycloakConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request to OAuth provider. ", e);
        } catch (IOException e) {
            handleException(KeycloakConstants.ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER, e);
        }
        return null;
    }

    /**
     * This method returns the client representation related of a client with the given clientId in Keycloak
     * @param clientId Client id of a client in Keycloak
     * @return JSON representation of a client in Keycloak
     * @throws APIManagementException This is the custom exception class for API management
     */
    private JSONObject getClientById(String clientId) throws APIManagementException{
        String accessToken = getAccessToken();
        String keyCloakInstanceUrl = configuration.getParameter(KeycloakConstants.KEYCLOAK_INSTANCE_URL);
        String keycloakRealm = configuration.getParameter(KeycloakConstants.KEYCLOAK_REALM_NAME);
        String clientSecretEndpoint = keyCloakInstanceUrl + KeycloakConstants.KEYCLOAK_ADMIN_CONTEXT + keycloakRealm +
                KeycloakConstants.CLIENT_ENDPOINT + clientId;
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build();) {
            HttpGet httpGet = new HttpGet(clientSecretEndpoint);
            httpGet.setHeader(KeycloakConstants.AUTHORIZATION, KeycloakConstants.AUTHENTICATION_BEARER + accessToken);
            HttpResponse response = httpClient.execute(httpGet);
            int statusCode = response.getStatusLine().getStatusCode();
            if (HttpStatus.SC_OK == statusCode) {
                HttpEntity entity = response.getEntity();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeycloakConstants.UTF_8));) {
                    JSONObject responseJSON = getParsedObjectByReader(reader);
                    return responseJSON;
                }
            }
        } catch (ParseException e) {
            handleException(KeycloakConstants.ERROR_WHILE_PARSE_RESPONSE, e);
        } catch (UnsupportedEncodingException e) {
            handleException(KeycloakConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request to OAuth provider. ", e);
        } catch (IOException e) {
            handleException(KeycloakConstants.ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER, e);
        }
        return null;
    }

    /**
     * Update the access token info after getting new access token.
     *
     * @param tokenInfo    Token info need to be updated.
     * @param responseJSON AccessTokenInfo
     * @return AccessTokenInfo
     */
    private AccessTokenInfo updateTokenInfo(AccessTokenInfo tokenInfo, JSONObject responseJSON) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Update the access token info with JSON response: %s, after getting " +
                    "new access token.", responseJSON));
        }
        tokenInfo.setAccessToken((String) responseJSON.get(KeycloakConstants.ACCESS_TOKEN));
        Long expireTime = (Long) responseJSON.get(KeycloakConstants.ACCESS_TOKEN_EXPIRES_IN);

        if (expireTime == null) {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            return tokenInfo;
        }
        tokenInfo.setValidityPeriod(expireTime);

        String tokenScopes = (String) responseJSON.get(KeycloakConstants.ACCESS_TOKEN_SCOPE);
        if (StringUtils.isNotEmpty(tokenScopes)) {
            tokenInfo.setScope(tokenScopes.split("\\s+"));
        }

        tokenInfo.setTokenValid(Boolean.parseBoolean(KeycloakConstants.ACCESS_TOKEN_ACTIVE));
        tokenInfo.setTokenState(KeycloakConstants.ACCESS_TOKEN_ACTIVE);

        return tokenInfo;
    }
}
