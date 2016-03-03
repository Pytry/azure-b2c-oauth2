package com.dogjaw.services.authentication.b2c;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Keith Hoopes on 3/2/2016.
 *
 * This is not used, bit eventually we should use it to connect to a database for user retrieval and creation.
 */
@SuppressWarnings("unused")
@Service
@ConfigurationProperties("azure.client")
public class AoidUserDetailsManager implements UserDetailsManager {

    @Autowired
    private MetaDataClient metaDataClient;

    private Map<String,String> requestParameters;
    private String responseType;
    private String redirectUri;
    private String responseMode;
    private String scope;
    private String state;
    private String nonce;

    @Override
    public void createUser(UserDetails user) {

        AzurePolicyMetaData meta = metaDataClient.getSignupMetaData();
        assert (meta.getResponseTypesSupported()).contains(responseType);

        initRequestParameters();

        String redirect = meta.getAuthorizationEndpoint();

        throw new UserRedirectRequiredException(redirect, requestParameters);
    }

    private void initRequestParameters(){

        if(requestParameters == null){

            requestParameters = new HashMap<>();
            requestParameters.put("response_type", responseType);
            requestParameters.put("redirect_uri", redirectUri);
            requestParameters.put("response_mode", responseMode);
            requestParameters.put("scope", scope);
            requestParameters.put("state", state);
            requestParameters.put("nonce", nonce);
        }
    }

    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {

        return false;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return null;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public void setState(String state) {
        this.state = state;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }
}
