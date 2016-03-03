package com.dogjaw.services.authentication.b2c;

import com.dogjaw.services.authentication.services.RsaKeyCachingService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.Map;

/**
 * Created by Keith Hoopes on 2/26/2016.
 *
 * Overrides the decode method to add azure specific details, and ot compensate
 * for details that it leaves out.
 */
public class AoidJwtAccessTokenConverter extends JwtAccessTokenConverter {

    private final String NBF = "nbf";
    private final String NAME = "name";

    private final JsonParser jsonParser = JsonParserFactory.create();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private RsaKeyCachingService rsaKeyCachingService;
    private UserDetailsManager userDetailsService;
    private AuthorizationCodeResourceDetails authenticationDetails;

    public AoidJwtAccessTokenConverter(RsaKeyCachingService rsaKeyCachingService, UserDetailsManager userDetailsService, AuthorizationCodeResourceDetails authenticationDetails) {
        assert rsaKeyCachingService != null;

        this.rsaKeyCachingService = rsaKeyCachingService;
        this.userDetailsService = userDetailsService;
        this.authenticationDetails = authenticationDetails;
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
            String kid = jwt.getHeader().getKid();
//            RsaVerifier rsaVerifier = rsaKeyCachingService.getRsaVerifier(kid);
//            jwt.verifySignature(rsaVerifier);

            UserClaims userClaims = objectMapper.convertValue(map, UserClaims.class);
            if (userClaims.isCredentialsNonExpired()) {

                if (userDetailsService.userExists(userClaims.getUsername())) {

                    userDetailsService.updateUser(userClaims);
                }
                else {

                    userDetailsService.createUser(userClaims);
                }
            }
            map.put(CLIENT_ID, authenticationDetails.getClientId());

            return map;
        }
        catch (IllegalArgumentException e) {

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
