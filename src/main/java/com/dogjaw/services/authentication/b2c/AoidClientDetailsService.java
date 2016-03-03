package com.dogjaw.services.authentication.b2c;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

/**
 * Created by Keith Hoopes on 3/2/2016.
 * Copyright Bear River Mutual 2016.
 */
public class AoidClientDetailsService implements ClientDetailsService {
    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        return null;
    }
}
