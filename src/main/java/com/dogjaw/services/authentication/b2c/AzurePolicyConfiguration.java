package com.dogjaw.services.authentication.b2c;

/**
 * Created by Keith Hoopes on 2/24/2016.
 * Copyright Bear River Mutual 2016.
 *
 * Azure B2C is a Trademark of Microsoft Corporation
 *
 * Used to hold properties about the policies used in Azure.
 */
@SuppressWarnings("unused")
public class AzurePolicyConfiguration {

    private String signinPolicy;
    private String signupPolicy;
    private String editProfilePolicy;
    private String wellknownUrl;
    private String rsaKeyLocation;
    private String signinRsaKeyName;
    private String signupRsaKeyName;
    private String editProfileRsaKeyName;

    public String getSigninPolicy() {
        return signinPolicy;
    }

    public void setSigninPolicy(String signinPolicy) {
        this.signinPolicy = signinPolicy;
    }

    public String getSignupPolicy() {
        return signupPolicy;
    }

    public void setSignupPolicy(String signupPolicy) {
        this.signupPolicy = signupPolicy;
    }

    public String getEditProfilePolicy() {
        return editProfilePolicy;
    }

    public void setEditProfilePolicy(String editProfilePolicy) {
        this.editProfilePolicy = editProfilePolicy;
    }

    public String getWellknownUrl() {
        return wellknownUrl;
    }

    public void setWellknownUrl(String wellknownUrl) {
        this.wellknownUrl = wellknownUrl;
    }

    public String getRsaKeyLocation() {
        return rsaKeyLocation;
    }

    public void setRsaKeyLocation(String rsaKeyLocation) {
        this.rsaKeyLocation = rsaKeyLocation;
    }

    public String getSigninRsaKeyName() {
        return signinRsaKeyName;
    }

    public void setSigninRsaKeyName(String signinRsaKeyName) {
        this.signinRsaKeyName = signinRsaKeyName;
    }

    public String getSignupRsaKeyName() {
        return signupRsaKeyName;
    }

    public void setSignupRsaKeyName(String signupRsaKeyName) {
        this.signupRsaKeyName = signupRsaKeyName;
    }

    public String getEditProfileRsaKeyName() {
        return editProfileRsaKeyName;
    }

    public void setEditProfileRsaKeyName(String editProfileRsaKeyName) {
        this.editProfileRsaKeyName = editProfileRsaKeyName;
    }
}
