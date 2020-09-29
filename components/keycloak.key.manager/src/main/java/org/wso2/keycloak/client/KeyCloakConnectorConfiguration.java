package org.wso2.keycloak.client;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * KeyCloak Connector information.
 */
@Component(
        name = "keycloak.configuration.component",
        immediate = true,
        service = KeyManagerConnectorConfiguration.class
)
public class KeyCloakConnectorConfiguration implements KeyManagerConnectorConfiguration {

    @Override
    public String getImplementation() {

        return KeycloakClient.class.getName();
    }

    @Override
    public String getJWTValidator() {

        return null;
    }

    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto("client_id", "Client ID", "input", "Client ID of service Application", "",
                        true,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("client_secret", "Client Secret", "input",
                        "Client Secret of service Application", "", true,
                        true, Collections.emptyList(), false));
        return configurationDtoList;
    }

    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto("response_types", "Response Type", "select", "Type Of Token response", "",
                        false,
                        false, Arrays.asList("code", "none", "id_token", "token", "id_token token", "code id_token",
                        "code token", "code id_token token"), true));
        configurationDtoList
                .add(new ConfigurationDto("subject_type", "Subject Type", "select", "Subject Type of Client", 
                        "pairwise", true, false, Arrays.asList("public", "pairwise"), false));
        configurationDtoList
                .add(new ConfigurationDto("token_endpoint_auth_method", "Token endpoint Authentication Method",
                        "select", "How to Authenticate Token Endpoint", "client_secret_basic", true,
                        false,
                        Arrays.asList("private_key_jwt", "client_secret_basic", "client_secret_post", "tls_client_auth",
                                "client_secret_jwt"), false));
        configurationDtoList
                .add(new ConfigurationDto("tls_client_certificate_bound_access_tokens",
                        "OAuth 2.0 Mutual TLS Certificate Bound Access Tokens Enabled",
                        "select", "Generate Certificate Bound Oauth2 Token", "false", true,
                        false, Arrays.asList("false", "true"), false));
        return configurationDtoList;
    }

    @Override
    public String getType() {

        return KeycloakConstants.KEY_CLOAK_TYPE;
    }
}
