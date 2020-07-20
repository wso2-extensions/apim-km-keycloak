package org.wso2.keycloak.client;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.recommendationmgt.AccessTokenGenerator;

/**
 * Bearer interceptor to send Bearer header
 */
public class BearerInterceptor implements RequestInterceptor {

    private AccessTokenGenerator accessTokenGenerator;

    public BearerInterceptor(AccessTokenGenerator accessTokenGenerator) {

        this.accessTokenGenerator = accessTokenGenerator;
    }

    @Override
    public void apply(RequestTemplate requestTemplate) {

        String accessToken = accessTokenGenerator.getAccessToken();
        requestTemplate
                .header(APIConstants.AUTHORIZATION_HEADER_DEFAULT, APIConstants.AUTHORIZATION_BEARER + accessToken);
    }
}
