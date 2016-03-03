package com.dogjaw.services.authentication.b2c;

/**
 * Created by Keith Hoopes on 2/24/2016.
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
}
