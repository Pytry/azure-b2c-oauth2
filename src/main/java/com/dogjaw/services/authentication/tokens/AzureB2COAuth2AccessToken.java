package com.dogjaw.services.authentication.tokens;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Date;
import java.util.Map;

/**
 * Created by Keith Hoopes on 2/3/2016.
 * Copyright Bear River Mutual 2016.
 *
 * Represents an OpenID Token
 */
public class AzureB2COAuth2AccessToken extends DefaultOAuth2AccessToken{

    private Date refreshTokenExpiration;
    private String profileInfo;
    private Date notBefore;

    public AzureB2COAuth2AccessToken(String value) {

        super(value);
        parseAzureTokenInformation(this);
    }

    public AzureB2COAuth2AccessToken(OAuth2AccessToken accessToken) {

        super(accessToken);

        DefaultOAuth2AccessToken token;

        if(accessToken instanceof  DefaultOAuth2AccessToken){

            token = (DefaultOAuth2AccessToken) accessToken;
        }
        else{

            token = new DefaultOAuth2AccessToken(accessToken);
        }
        parseAzureTokenInformation(token);
    }

    private void parseAzureTokenInformation(DefaultOAuth2AccessToken accessToken) {

        long now = System.currentTimeMillis();
        Map<String, Object> info = accessToken.getAdditionalInformation();

        if (info != null && info.size() > 0) {

            if (this.getValue() == null) {

                String idToken = (String) info.get("id_token");
//                String idToken = (String) info.get("profile_info");
                this.setValue(idToken);
            }

            if (this.getExpiration() == null) {

                String expiresInStr = (String) info.get("id_token_expires_in");

                if (expiresInStr != null) {

                    long seconds = Long.parseLong(expiresInStr);
                    long milliSeconds = seconds * 1000;
                    Date expiration = new Date(now + milliSeconds);

                    accessToken.setExpiration(expiration);
                }
            }

            String refreshExpiresInStr = (String) info.get("refresh_token_expires_in");
            if (refreshExpiresInStr != null) {

                long seconds = Long.parseLong(refreshExpiresInStr);
                long milliSeconds = seconds * 1000;
                this.refreshTokenExpiration = new Date(now + milliSeconds);
            }

            String notBeforeStr = (String) info.get("not_before");
            if (notBeforeStr != null) {

                long seconds = Long.parseLong(notBeforeStr);
                long milliSeconds = seconds * 1000;
                this.notBefore = new Date(now + milliSeconds);
            }

            String profile64Encoded = (String) info.get("profile_info");
            byte[] profileBytes = Base64.decode(profile64Encoded.getBytes());
            String profileJson = new String(profileBytes);
            //Change this to a Map or a UserObject?
            this.profileInfo = profileJson;

        }
    }

    public Date getRefreshTokenExpiration() {

        return refreshTokenExpiration;
    }

    public String getProfileInfo() {

        return profileInfo;
    }

    public Date getNotBefore() {

        return notBefore;
    }
}
