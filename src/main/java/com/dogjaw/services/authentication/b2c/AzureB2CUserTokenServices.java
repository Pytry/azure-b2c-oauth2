package com.dogjaw.services.authentication.b2c;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;

/**
 * Created by Keith Hoopes on 2/3/2016.
 * Copyright Bear River Mutual 2016.
 */
public class AzureB2CUserTokenServices extends UserInfoTokenServices {

    private final String userInfoEndpointUrl;

    public AzureB2CUserTokenServices(String userInfoEndpointUrl, String clientId) {

        super(userInfoEndpointUrl, clientId);
        this.userInfoEndpointUrl = userInfoEndpointUrl;
    }

//    @Override
//    public OAuth2Authentication loadAuthentication(String accessToken)
//            throws AuthenticationException, InvalidTokenException {
//
////        Map<String, Object> map = getMap(this.userInfoEndpointUrl, accessToken);
////        if (map.containsKey("error")) {
////            this.logger.debug("userinfo returned error: " + map.get("error"));
////            throw new InvalidTokenException(accessToken);
////        }
////        return extractAuthentication(map);
//    }
}
