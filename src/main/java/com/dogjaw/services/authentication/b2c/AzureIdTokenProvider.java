package com.dogjaw.services.authentication.b2c;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.io.IOException;

/**
 * Created by Keith Hoopes on 2/3/2016.
 */
public class AzureIdTokenProvider extends AuthorizationCodeAccessTokenProvider {

    @Override
    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
            throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException, OAuth2AccessDeniedException {

        OAuth2AccessToken accessToken = super.obtainAccessToken(details, request);

        AzureAccessToken azureAccessToken;
        try {
            azureAccessToken = new AzureAccessToken(accessToken);
        }
        catch (IOException e) {
            e.printStackTrace();
            throw new AccessDeniedException("Could not create AzureAccessToken.",e);
        }
        return azureAccessToken;
    }
}
