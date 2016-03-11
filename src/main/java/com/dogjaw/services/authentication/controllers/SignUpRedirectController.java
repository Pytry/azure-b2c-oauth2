package com.dogjaw.services.authentication.controllers;

import com.dogjaw.services.authentication.b2c.AzurePolicyConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * Created by Keith Hoopes on 3/11/2016. *
 * <p/>
 * Because of the complex nature of the sign-up url, it made sense to create a separate controller
 * to handle it's creation based off of configuration, as opposed to having it in the MvcConfig
 */
@SuppressWarnings("unused")
@Controller
@ConfigurationProperties("azure.client")
public class SignUpRedirectController {

    @Autowired
    private AzurePolicyConfiguration policyConfiguration;

    private String userAccountSignupUri;
    private String clientId;
    private String responseType;
    private String scope;
    private String redirectUrl;
    private String responseMode;

    @SuppressWarnings("UnnecessaryLocalVariable")
    @RequestMapping("/signup/azure")
    public String signupAzure() throws UnsupportedEncodingException {

        String signupRequest = String.format("redirect:" + userAccountSignupUri +
                        "&client_id=%s" +
                        "&response_type=%s" +
                        "&redirect_uri=%s" +
                        "&response_mode=%s" +
                        "&scope=%s" +
                        "&state=%s" +
                        "&nonce=%s"
                , encode(clientId)
                , encode(responseType)
                , encode(redirectUrl)
                , encode(responseMode)
                , encode(scope)
                , encode(policyConfiguration.getSignupPolicy())
                , encode(BCrypt.gensalt()));

        return signupRequest;
    }

    private String encode(String value) throws UnsupportedEncodingException {

        return URLEncoder.encode(value, "UTF-8");
    }

    public void setPolicyConfiguration(AzurePolicyConfiguration policyConfiguration) {
        this.policyConfiguration = policyConfiguration;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
    }

    public void setUserAccountSignupUri(String userAccountSignupUri) {
        this.userAccountSignupUri = userAccountSignupUri;
    }
}
