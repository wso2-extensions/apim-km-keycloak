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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import feign.Feign;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.okhttp.OkHttpClient;
import feign.slf4j.Slf4jLogger;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.api.model.URITemplate;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.kmclient.FormEncoder;
import org.wso2.carbon.apimgt.impl.recommendationmgt.AccessTokenGenerator;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.keycloak.client.model.AccessTokenInfo;
import org.wso2.keycloak.client.model.ClientInfo;
import org.wso2.keycloak.client.model.DCRClient;
import org.wso2.keycloak.client.model.IntrospectInfo;
import org.wso2.keycloak.client.model.IntrospectionClient;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class provides the implementation to use "Keycloak" for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class KeycloakClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(KeycloakClient.class);
    private DCRClient dcrClient;
    private IntrospectionClient introspectionClient;

    /**
     * {@code APIManagerComponent} calls this method, passing KeyManagerConfiguration as a {@code String}.
     *
     * @param keyManagerConfiguration Configuration as a {@link KeyManagerConfiguration}
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {

        this.configuration = keyManagerConfiguration;
        String clientRegistrationEndpoint =
                (String) configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT);
        String clientId = (String) configuration.getParameter(KeycloakConstants.CLIENT_ID);
        String clientSecret = (String) configuration.getParameter(KeycloakConstants.CLIENT_SECRET);
        BasicAuthRequestInterceptor basicAuthRequestInterceptor =
                new BasicAuthRequestInterceptor(clientId, clientSecret);
        String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
        String revokeEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.REVOKE_ENDPOINT);
        Gson gson = new GsonBuilder().serializeNulls().create();
        if (StringUtils.isNotEmpty(clientId) && StringUtils.isNotEmpty(clientSecret) &&
                StringUtils.isNotEmpty(tokenEndpoint) && StringUtils.isNotEmpty(revokeEndpoint)) {
            AccessTokenGenerator accessTokenGenerator =
                    new AccessTokenGenerator(tokenEndpoint, revokeEndpoint, clientId,
                            clientSecret);
            dcrClient =
                    Feign.builder().client(new OkHttpClient()).decoder(new GsonDecoder(gson))
                            .encoder(new GsonEncoder(gson))
                            .requestInterceptor(new BearerInterceptor(accessTokenGenerator))
                            .target(DCRClient.class, clientRegistrationEndpoint);
            String introspectEndpoint =
                    (String) configuration.getParameter(APIConstants.KeyManager.INTROSPECTION_ENDPOINT);
            introspectionClient =
                    Feign.builder().client(new OkHttpClient()).encoder(new GsonEncoder(gson))
                            .decoder(new GsonDecoder(gson))
                            .logger(new Slf4jLogger())
                            .requestInterceptor(basicAuthRequestInterceptor)
                            .encoder(new FormEncoder()).target(IntrospectionClient.class, introspectEndpoint);
        } else {
            throw new APIManagementException("Error while configuring Keycloak Connector");
        }
    }

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        if (oAuthApplicationInfo != null) {
            ClientInfo clientInfoFromOauthApplicationInfo =
                    createClientInfoFromOauthApplicationInfo(oAuthApplicationInfo);
            ClientInfo createdApplication = dcrClient.createApplication(clientInfoFromOauthApplicationInfo);
            if (createdApplication != null) {
                oAuthApplicationInfo = createOAuthAppInfoFromResponse(createdApplication);
                return oAuthApplicationInfo;
            }
        }
        return null;
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        if (oAuthApplicationInfo != null) {
            String clientId = oAuthApplicationInfo.getClientId();
            // We have to send the client id with the update request.
            if (log.isDebugEnabled()) {
                log.debug(String.format(
                        "Updating an OAuth client in Keycloak authorization server for the Consumer Key %s",
                        clientId));
            }
            ClientInfo clientInfoFromOauthApplicationInfo =
                    createClientInfoFromOauthApplicationInfo(oAuthApplicationInfo);
            ClientInfo clientInfo = dcrClient.updateApplication(clientId, clientInfoFromOauthApplicationInfo);
            if (clientInfo != null) {
                oAuthApplicationInfo = createOAuthAppInfoFromResponse(clientInfo);
                return oAuthApplicationInfo;
            }
        }
        return null;
    }

    @Override
    public void deleteApplication(String clientId) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug(
                    String.format("Deleting an OAuth client in Keycloak authorization server for the Consumer Key: %s",
                            clientId));
        }
        dcrClient.deleteApplication(clientId);
    }

    @Override
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {

        if (StringUtils.isNotEmpty(clientId)) {
            ClientInfo application = dcrClient.getApplication(clientId);
            return createOAuthAppInfoFromResponse(application);
        }
        return null;
    }

    @Override
    public org.wso2.carbon.apimgt.api.model.AccessTokenInfo getNewApplicationAccessToken(
            AccessTokenRequest accessTokenRequest)
            throws APIManagementException {

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
        AccessTokenInfo retrievedAccessTokenInfo = getAccessToken(clientId, clientSecret, parameters);
        if (retrievedAccessTokenInfo != null) {
            org.wso2.carbon.apimgt.api.model.AccessTokenInfo accessTokenInfo =
                    new org.wso2.carbon.apimgt.api.model.AccessTokenInfo();
            accessTokenInfo.setConsumerKey(clientId);
            accessTokenInfo.setConsumerSecret(clientSecret);
            accessTokenInfo.setAccessToken(retrievedAccessTokenInfo.getAccessToken());
            accessTokenInfo.setScope(retrievedAccessTokenInfo.getScope().split("\\s+"));
            accessTokenInfo.setValidityPeriod(retrievedAccessTokenInfo.getExpiry());
            return accessTokenInfo;
        }
        return null;
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest accessTokenRequest) throws APIManagementException {

        return null;
    }

    @Override
    public org.wso2.carbon.apimgt.api.model.AccessTokenInfo getTokenMetaData(String accessToken)
            throws APIManagementException {

        org.wso2.carbon.apimgt.api.model.AccessTokenInfo tokenInfo =
                new org.wso2.carbon.apimgt.api.model.AccessTokenInfo();
        IntrospectInfo introspectInfo =
                introspectionClient.introspect(accessToken, KeycloakConstants.REQUESTING_PARTY_TOKEN);
        if (introspectInfo != null) {
            tokenInfo.setAccessToken(accessToken);
            tokenInfo.setTokenValid(introspectInfo.isActive());
            tokenInfo.setIssuedTime(introspectInfo.getIssuedAt());
            tokenInfo.setValidityPeriod(introspectInfo.getExpiryTime() - introspectInfo.getIssuedAt());
            tokenInfo.setEndUserName(introspectInfo.getUsername());
            tokenInfo.setConsumerKey(introspectInfo.getConsumerKey());
            if (StringUtils.isNotEmpty(introspectInfo.getScope())) {
                tokenInfo.setScope(introspectInfo.getScope().split("\\s+"));
            }
            tokenInfo.addParameter(KeycloakConstants.ACCESS_TOKEN_ISSUER, introspectInfo.getIssuer());
            tokenInfo.addParameter(KeycloakConstants.ACCESS_TOKEN_IDENTIFIER, introspectInfo.getJti());
        }
        return tokenInfo;
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
        if (oAuthApplication.getClientSecret() == null) {
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
        String consumerKey = oAuthAppRequest.getOAuthApplicationInfo().getClientId();
        String consumerSecret = oAuthAppRequest.getOAuthApplicationInfo().getClientSecret();

        if (StringUtils.isNotBlank(consumerKey)) {
            OAuthApplicationInfo clientInfo = retrieveApplication(consumerKey);
            if (clientInfo == null) {
                handleException(
                        "Something went wrong while getting OAuth application for given consumer key " + consumerKey);
            }

            if (StringUtils.isNotBlank(consumerSecret) && !consumerSecret.equals(clientInfo.getClientSecret())) {
                throw new APIManagementException("The secret key is wrong for the given consumer key " + consumerKey);
            }

            return oAuthAppRequest.getOAuthApplicationInfo();
        }

        throw new APIManagementException("Consumer credentials are blank");
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
    public org.wso2.carbon.apimgt.api.model.AccessTokenInfo getAccessTokenByConsumerKey(String s)
            throws APIManagementException {

        return null;
    }

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String s) throws APIManagementException {

        return null;
    }

    @Override
    public void registerScope(Scope scope) throws APIManagementException {

    }

    @Override
    public Scope getScopeByName(String s) throws APIManagementException {

        return null;
    }

    @Override
    public Map<String, Scope> getAllScopes() throws APIManagementException {

        return null;
    }

    @Override
    public void attachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {

    }

    @Override
    public void updateResourceScopes(API api, Set<String> oldLocalScopeKeys, Set<Scope> newLocalScopes,
                                     Set<URITemplate> oldURITemplates, Set<URITemplate> newURITemplates)
            throws APIManagementException {

    }

    @Override
    public void detachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {

    }

    @Override
    public void deleteScope(String s) throws APIManagementException {

    }

    @Override
    public void updateScope(Scope scope) throws APIManagementException {

    }

    @Override
    public boolean isScopeExists(String s) throws APIManagementException {

        return false;
    }

    @Override
    public void validateScopes(Set<Scope> scopes) throws APIManagementException {

    }

    @Override
    public String getType() {

        return KeycloakConstants.KEY_CLOAK_TYPE;
    }

    /**
     * This method will create {@code OAuthApplicationInfo} object from a {@link ClientInfo}
     *
     * @param clientInfo Response returned from server as {@link ClientInfo}
     * @return OAuthApplicationInfo object will return.
     */
    private OAuthApplicationInfo createOAuthAppInfoFromResponse(ClientInfo clientInfo) {

        OAuthApplicationInfo appInfo = new OAuthApplicationInfo();
        appInfo.setClientName(clientInfo.getClientName());
        appInfo.setClientId(clientInfo.getClientId());
        appInfo.setClientSecret(clientInfo.getClientSecret());
        appInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_NAME, clientInfo.getClientName());
        if (clientInfo.getCallBackUrls() != null) {
            appInfo.setCallBackURL(String.join(",", clientInfo.getCallBackUrls()));
        }

        if (clientInfo.getGrantTypes() != null) {
            appInfo.addParameter(KeycloakConstants.CLIENT_GRANT_TYPES, String.join(" ", clientInfo.getGrantTypes()));
        }
        String additionalProperties = new Gson().toJson(clientInfo);
        appInfo.addParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES,
                new Gson().fromJson(additionalProperties, Map.class));
        return appInfo;
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
     * Gets an access token.
     *
     * @param clientId     clientId of the oauth client.
     * @param clientSecret clientSecret of the oauth client.
     * @param parameters   list of request parameters.
     * @return an {@code JSONObject}
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private AccessTokenInfo getAccessToken(String clientId, String clientSecret,
                                           List<NameValuePair> parameters) throws
            APIManagementException {

        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
            HttpPost httpPost = new HttpPost(tokenEndpoint);
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));
            String encodedCredentials = getEncodedCredentials(clientId, clientSecret);

            httpPost.setHeader(KeycloakConstants.AUTHORIZATION,
                    KeycloakConstants.AUTHENTICATION_BASIC + encodedCredentials);
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get the accesstoken.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(KeycloakConstants.STRING_FORMAT,
                        KeycloakConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            if (org.apache.commons.httpclient.HttpStatus.SC_OK == statusCode) {

                try (InputStream inputStream = entity.getContent()) {
                    String content = IOUtils.toString(inputStream);
                    return new Gson().fromJson(content, AccessTokenInfo.class);

                }
            }
        } catch (UnsupportedEncodingException e) {
            handleException(KeycloakConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        } catch (IOException e) {
            handleException(KeycloakConstants.ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER, e);
        }
        return null;
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
     * method to update application owner (change ownership from admin portal :
     * supported from 2.6)
     *
     * @param oAuthAppRequest Parameters to be passed to Authorization Server,
     *                        encapsulated as an {@code OAuthAppRequest}
     * @param owner
     * @return Details of updated OAuth Client
     * @throws APIManagementException This is the custom exception class for API
     *                                management
     */
    public OAuthApplicationInfo updateApplicationOwner(OAuthAppRequest oAuthAppRequest, String owner)
            throws APIManagementException {

        return oAuthAppRequest.getOAuthApplicationInfo();
    }

    /**
     * This method can be used to create a JSON Payload out of the Parameters defined in an OAuth Application
     * in order to create and update the client.
     *
     * @param oAuthApplicationInfo Object that needs to be converted.
     * @return JSON payload.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private ClientInfo createClientInfoFromOauthApplicationInfo(OAuthApplicationInfo oAuthApplicationInfo)
            throws APIManagementException {

        ClientInfo clientInfo = new ClientInfo();
        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.
                OAUTH_CLIENT_USERNAME);
        String userNameForSp = MultitenantUtils.getTenantAwareUsername(userId);
        String domain = UserCoreUtil.extractDomainFromName(userNameForSp);
        if (domain != null && !domain.isEmpty() && !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(domain)) {
            userNameForSp = userNameForSp.replace(UserCoreConstants.DOMAIN_SEPARATOR, "_");
        }
        String applicationName = oAuthApplicationInfo.getClientName();
        String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);
        String callBackURL = oAuthApplicationInfo.getCallBackURL();
        if (keyType != null) {
            applicationName = userNameForSp.concat(applicationName).concat("_").concat(keyType);
        }
        List<String> grantTypes = new ArrayList<>();

        if (oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES) != null) {
            grantTypes =
                    Arrays.asList(
                            ((String) oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES)).split(","));
        }
        Object parameter = oAuthApplicationInfo.getParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES);
        Map<String, Object> additionalProperties = new HashMap<>();
        if (parameter instanceof String) {
            additionalProperties = new Gson().fromJson((String) parameter, Map.class);
        }
        clientInfo.setClientName(applicationName);
        if (!grantTypes.isEmpty()) {
            clientInfo.setGrantTypes(grantTypes);
        }
        if (StringUtils.isNotEmpty(callBackURL)) {
            String[] calBackUris = callBackURL.split(",");
            clientInfo.setCallBackUrls(Arrays.asList(calBackUris));
        }
        if (additionalProperties.containsKey(KeycloakConstants.SUBJECT_TYPE)) {
            clientInfo.setSubjectType((String) additionalProperties.get(KeycloakConstants.SUBJECT_TYPE));
        }

        if (additionalProperties.containsKey(KeycloakConstants.CLIENT_ID)) {
            clientInfo.setClientId((String) additionalProperties.get(KeycloakConstants.CLIENT_ID));
        }

        if (additionalProperties.containsKey(KeycloakConstants.CLIENT_SECRET)) {
            clientInfo.setClientSecret((String) additionalProperties.get(KeycloakConstants.CLIENT_SECRET));
        }
        if (additionalProperties.get(KeycloakConstants.CLIENT_RESPONSE_TYPES) instanceof List) {
            clientInfo
                    .setResponseTypes((List<String>) additionalProperties.get(KeycloakConstants.CLIENT_RESPONSE_TYPES));
        }
        if (additionalProperties.containsKey(KeycloakConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD)) {
            clientInfo.setTokenEndpointAuthenticationMethod(
                    (String) additionalProperties.get(KeycloakConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD));
        }
        if (additionalProperties.containsKey(KeycloakConstants.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKEN)) {
            Object clientBoundAccessToken =
                    additionalProperties.get(KeycloakConstants.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKEN);
            if (clientBoundAccessToken instanceof Boolean) {
                clientInfo.setEnableClientCertificateBindAccessToken((Boolean) clientBoundAccessToken);
            } else if (clientBoundAccessToken instanceof String) {
                clientInfo.setEnableClientCertificateBindAccessToken(
                        Boolean.parseBoolean((String) clientBoundAccessToken));
            }
        }
        return clientInfo;
    }
}
