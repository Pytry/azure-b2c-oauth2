package com.dogjaw.services.authentication.b2c;

import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Map;

/**
 * Created by Keith Hoopes on 2/26/2016.
 * Copyright Bear River Mutual 2016.
 */
public class AzureJwtAccessTokenConverter extends JwtAccessTokenConverter {

    private JsonParser objectMapper = JsonParserFactory.create();

    @Override
    protected Map<String, Object> decode(String token) {

        try{
            //TODO: Ideally, this should call super before calling the private verify for Azure specific verification.        try {
            Jwt jwt = JwtHelper.decode(token);
            verify(jwt);
            String content = jwt.getClaims();
            Map<String, Object> map = objectMapper.parseMap(content);
            if (map.containsKey(EXP) && map.get(EXP) instanceof Integer) {
                Integer intValue = (Integer) map.get(EXP);
                map.put(EXP, new Long(intValue));
            }
            return map;
        }
        catch (Exception e) {
            throw new InvalidTokenException("Cannot convert access token to JSON", e);
        }
    }

    private void verify(Jwt jwt){
        //TODO: add verification logic
    }
}
