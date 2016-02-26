package com.dogjaw.services.authentication.services;

import com.dogjaw.services.authentication.b2c.AzureRsaKeys;
import com.dogjaw.services.authentication.b2c.RsaKeyClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * Created by Keith Hoopes on 2/25/2016.
 * Copyright Bear River Mutual 2016.
 */
@Service
public class RsaKeyCachingService {

    @Autowired
    private RsaKeyClient rsaKeyClient;

    private ObjectMapper mapper = new ObjectMapper();

    @Scheduled(cron = "${azure.policy.refresh-cron}")
    public void refreshRsaKeys() throws IOException {

        expireCache();
        //TODO: Also reload security context?
    }

    /**
     * Reloads the RSA keys for the signin, signup, and edit-profile policies
     * @throws IOException
     */
    @CacheEvict(allEntries = true,beforeInvocation = true,cacheNames = {
            "SigninRsaKey","SignupRsaKey","EditProfileRsaKey"
    })
    public void expireCache() throws IOException {}

    /**
     * Reloads the RSA key for the signin policy
     * @throws IOException
     */
    @Cacheable("SigninRsaKey")
    public AzureRsaKeys getSigninRsaKey() throws IOException {

        String b2c = rsaKeyClient.getSigninRsaKey();
        AzureRsaKeys azureRsaKeys = mapper.readValue(b2c, AzureRsaKeys.class);
        azureRsaKeys.setOriginalValue(b2c);//Just for debugging right now.
        return azureRsaKeys;
    }

    /**
     * Reloads the RSA key for the signup policy
     * @throws IOException
     */
    @Cacheable("SignupRsaKey")
    public AzureRsaKeys getSignupRsaKey() throws IOException {

        String b2c = rsaKeyClient.getSignupRsaKey();
        return mapper.readValue(b2c, AzureRsaKeys.class);
    }

    /**
     * Reloads the RSA key for the edit-profile policy
     * @throws IOException
     */
    @Cacheable("SignupRsaKey")
    public AzureRsaKeys getEditProfileRsaKey() throws IOException {

        String b2c = rsaKeyClient.getEditProfileRsaKey();
        return mapper.readValue(b2c, AzureRsaKeys.class);
    }
}
