package com.dogjaw.services.authentication.tokens;

/**
 * Created by Keith Hoopes on 2/24/2016.
 * Copyright Bear River Mutual 2016.
 *
 * Azure B2C is a Trademark of Microsoft Corporation
 *
 * Used to hold properties about the policies used in Azure.
 */
public class AzurePolicy {

    private String signinPolicy;
    private String signUpPolicy;
    private String userDetailsPolicy;

    public String getSigninPolicy() {

        return signinPolicy;
    }

    public void setSigninPolicy(String signinPolicy) {

        this.signinPolicy = signinPolicy;
    }

    public String getSignUpPolicy() {
        return signUpPolicy;
    }

    public void setSignUpPolicy(String signUpPolicy) {
        this.signUpPolicy = signUpPolicy;
    }

    public String getUserDetailsPolicy() {
        return userDetailsPolicy;
    }

    public void setUserDetailsPolicy(String userDetailsPolicy) {
        this.userDetailsPolicy = userDetailsPolicy;
    }
}
