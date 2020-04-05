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

public class KeycloakConstants {
    public static final String UTF_8 = "UTF-8";
    public static final String HTTP_HEADER_CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_JSON = "application/json";
    public static final String APPLICATION_URL_ENCODED = "application/x-www-form-urlencoded";
    public static final String AUTHORIZATION = "Authorization";
    public static final String AUTHENTICATION_BASIC = "Basic ";
    public static final String AUTHENTICATION_BEARER = "Bearer ";
    public static final String JWT_AZP_CLAIM = "azp";
    public static final String CLIENT_ENDPOINT = "/clients/";
    public static final String GRANT_TYPE = "grant_type";
    public static final String GRANT_TYPE_PASSWORD = "password";
    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    public static final String GRANT_TYPE_IMPLICIT = "implicit";
    public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String GRANT_TYPE_PASSWORD_KEYCLOAK = "directAccessGrantsEnabled";
    public static final String GRANT_TYPE_AUTHORIZATION_CODE_KEYCLOAK = "standardFlowEnabled";
    public static final String GRANT_TYPE_IMPLICIT_KEYCLOAK = "implicitFlowEnabled";
    public static final String GRANT_TYPE_CLIENT_CREDENTIALS_KEYCLOAK = "serviceAccountsEnabled";
    public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    public static final String CALLBACK_URL = "callback_url";
    public static final String REDIRECT_URIS = "redirect_uris";
    public static final String ACCESS_TOKEN_SCOPE = "scope";
    public static final String CLIENT_REDIRECT_URIS = "redirectUris";
    public static final String CLIENT_GRANT_TYPES = "grant_types";
    public static final String CLIENT_NAME = "client_name";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String CLIENT_SECRET_VALUE = "value";
    public static final String TOKEN = "token";
    public static final String TOKEN_TYPE_HINT = "token_type_hint";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String ACCESS_TOKEN_ACTIVE = "active";
    public static final String ACCESS_TOKEN_EXPIRY = "exp";
    public static final String ACCESS_TOKEN_ISSUED = "iat";
    public static final String ACCESS_TOKEN_USER_NAME = "username";
    public static final String ACCESS_TOKEN_AUDIENCE = "aud";
    public static final String ACCESS_TOKEN_ISSUER = "iss";
    public static final String ACCESS_TOKEN_TYPE = "typ";
    public static final String ACCESS_TOKEN_SUBJECT = "sub";
    public static final String ACCESS_TOKEN_USER_ID = "username";
    public static final String ACCESS_TOKEN_IDENTIFIER = "jti";
    public static final String ACCESS_TOKEN_EXPIRES_IN = "expires_in";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String REFRESH_TOKEN_EXPIRES_IN = "refresh_expires_in";
    public static final String KEYCLOAK_INSTANCE_URL = "keycloakInstanceUrl";
    public static final String KEYCLOAK_REALM_NAME = "keycloakRealmName";
    public static final String KEYCLOAK_TOKEN_CONTEXT = "/auth/realms/";
    public static final String KEYCLOAK_TOKEN_PATH = "/protocol/openid-connect/token";
    public static final String KEYCLOAK_INTROSPECT_PATH = "/protocol/openid-connect/token/introspect";
    public static final String KEYCLOAK_ADMIN_CONTEXT = "/auth/admin/realms/";
    public static final String KEYCLOAK_CLIENT_SECRET_PATH = "/client-secret";
    public static final String KEYCLOAK_CLIENT_ID = "clientId";
    public static final String KEYCLOAK_ID = "id";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String TOKEN_SCOPE = "tokenScope";
    public static final String TOKEN_GRANT_TYPE = "tokenGrantType";
    public static final String ERROR_WHILE_PARSE_RESPONSE = "Error while parsing response json";
    public static final String ERROR_ENCODING_METHOD_NOT_SUPPORTED = "Encoding method is not supported";
    public static final String ERROR_COULD_NOT_READ_HTTP_ENTITY = "Could not read http entity for response";
    public static final String STRING_FORMAT = "%s %s";
    public static final String ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER = "Error has occurred while reading " +
            "or closing buffer reader";

    KeycloakConstants() {
    }
}
