package com.dogjaw.services.authentication.b2c;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultRequestEnhancer;
import org.springframework.util.MultiValueMap;

import java.util.Collections;
import java.util.List;

/**
 * Created by Keith Hoopes on 2/2/2016.
 */
public class AzureRequestEnhancer extends DefaultRequestEnhancer {

    @Override
    public void enhance(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form, HttpHeaders headers) {

        super.enhance(request, resource, form, headers);

        List<String> scopeList = resource.getScope();
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < scopeList.size(); i++) {

            if (i > 0) {
                builder.append(" ");
            }
            builder.append(scopeList.get(i));
        }
        form.set("scope", builder.toString());
        form.set("client_id", resource.getClientId());
        form.set("client_secret", resource.getClientSecret());

        headers.put("Content-Type", Collections.singletonList("application/json"));
    }
}