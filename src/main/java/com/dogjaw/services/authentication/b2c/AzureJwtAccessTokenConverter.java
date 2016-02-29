package com.dogjaw.services.authentication.b2c;

import com.dogjaw.services.authentication.services.RsaKeyCachingService;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Map;

/**
 * Created by Keith Hoopes on 2/26/2016.
 * Copyright Bear River Mutual 2016.
 */
public class AzureJwtAccessTokenConverter extends JwtAccessTokenConverter {

    private final String NBF = "nbf";
    private final String NAME = "name";

    private final JsonParser jsonParser = JsonParserFactory.create();
//    private final ObjectMapper objectMapper = new ObjectMapper();

    private final RsaKeyCachingService rsaKeyCachingService;

    public AzureJwtAccessTokenConverter(RsaKeyCachingService rsaKeyCachingService) {
        assert rsaKeyCachingService != null;

        this.rsaKeyCachingService = rsaKeyCachingService;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected Map<String, Object> decode(String token) {

        try {

            JwtB2C jwt = new JwtB2C(JwtHelper.decode(token));
            String content = jwt.getClaims();

            Map<String, Object> map = jsonParser.parseMap(content);

                                       if (map.containsKey(EXP)) {

                Object intValue = map.get(EXP);
                map.put(EXP, new Long(intValue.toString()));
            }

            if (map.containsKey(NBF)) {

                Object intValue = map.get(NBF);
                map.put(NBF, new Long(intValue.toString()));
            }

            if (map.containsKey(NAME)) {

                map.put(UserAuthenticationConverter.USERNAME, map.get(NAME));
            }
//            String kid = jwt.getHeader().getKid();
//            RsaVerifier rsaVerifier = rsaKeyCachingService.getRsaVerifier(kid);
//            jwt.verifySignature(rsaVerifier);

            return map;
        }
        catch(IllegalArgumentException e){

            throw new InvalidTokenException("Token did not match a valid RsaKey and Policy.", e);
        }
        catch (Exception e) {

            throw new InvalidTokenException("Cannot convert access token to JSON", e);
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        rsaKeyCachingService.refreshRsaKeys();
    }
}
