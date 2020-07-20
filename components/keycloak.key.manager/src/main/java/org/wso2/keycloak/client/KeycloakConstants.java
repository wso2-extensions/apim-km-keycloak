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

/**
 * Constants related to KeyCloak
 *
 */
public class KeycloakConstants {
    public static final String UTF_8 = "UTF-8";
    public static final String AUTHORIZATION = "Authorization";
    public static final String AUTHENTICATION_BASIC = "Basic ";
    public static final String GRANT_TYPE = "grant_type";
    public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String ACCESS_TOKEN_SCOPE = "scope";
    public static final String CLIENT_GRANT_TYPES = "grant_types";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String ACCESS_TOKEN_ISSUER = "iss";
    public static final String ACCESS_TOKEN_IDENTIFIER = "jti";

    public static final String TOKEN_SCOPE = "tokenScope";
    public static final String TOKEN_GRANT_TYPE = "tokenGrantType";
    public static final String ERROR_ENCODING_METHOD_NOT_SUPPORTED = "Encoding method is not supported";
    public static final String ERROR_COULD_NOT_READ_HTTP_ENTITY = "Could not read http entity for response";
    public static final String STRING_FORMAT = "%s %s";
    public static final String ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER = "Error has occurred while reading " +
            "or closing buffer reader";
    public static final String SUBJECT_TYPE = "subject_type";
    public static final String CLIENT_RESPONSE_TYPES = "response_types";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
    public static final String TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKEN = "tls_client_certificate_bound_access_tokens";
    public static final String KEY_CLOAK_TYPE = "KeyCloak";
    public static final String REQUESTING_PARTY_TOKEN = "requesting_party_token";

    KeycloakConstants() {
    }
}
