package com.dogjaw.services.authentication.b2c;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.client.RestTemplate;

import static org.springframework.http.HttpMethod.POST;

/**
 * Created by Keith Hoopes on 2/25/2016.
 * <p/>
 * Provides methods for retrieving and updating the RSA keys for the configured Azure policies.
 */
public class RsaKeyClient {

    private AzurePolicyConfiguration policy;

    private RestTemplate restTemplate;

    private HttpHeaders jsonHttpHeaders;

    private MetaDataClient metaDataClient;

    @Scheduled(cron="${azure.policy.rsa-keys-refresh-cron}")
    @CacheEvict(allEntries = true,beforeInvocation = true,cacheNames = {
            "getSigninRsaKey","getSignupRsaKey","getEditProfileRsaKey"
    })
    public void evictAll(){}
    /**
     * Retrieves the RsaKey for the signin policy.
     *
     * @return {@link String}
     */
    @Cacheable("getSigninRsaKey")
    public byte[] getSigninRsaKey() {

        AzurePolicyMetaData metaData = metaDataClient.getSigninMetaData();
        String policy = this.policy.getSigninPolicy();

        return getRemoteRsaKey(policy, metaData);
    }

    /**
     * Retrieves the RsaKey for the signup policy.
     *
     * @return {@link String}
     */
    @Cacheable("getSignupRsaKey")
    public byte[] getSignupRsaKey() {

        AzurePolicyMetaData metaData = metaDataClient.getSignupMetaData();
        String policy = this.policy.getSignupPolicy();

        return getRemoteRsaKey(policy, metaData);
    }

    /**
     * Retrieves the RsaKey for the edit-profile policy.
     *
     * @return {@link String}
     */
    @Cacheable("getEditProfileRsaKey")
    public byte[] getEditProfileRsaKey() {

        AzurePolicyMetaData metaData = metaDataClient.getEditProfileMetaData();
        String policy = this.policy.getEditProfilePolicy();

        return getRemoteRsaKey(policy, metaData);
    }

    /**
     * Retrieves the remote b2c RsaKey for the given meta-data.
     *
     * @return {@link String}
     */
    public byte[] getRemoteRsaKey(String policyName, AzurePolicyMetaData metaData) {

        assert jsonHttpHeaders != null;
        assert restTemplate != null;
        assert policyName != null;

        HttpEntity<byte[]> requestEntity = new HttpEntity<>(jsonHttpHeaders);
        String keysUrl = metaData.getJwksUri();//Note: This value includes the policy name in the URL query

        ResponseEntity<byte[]> result = restTemplate.exchange(
                keysUrl, POST, requestEntity, byte[].class);

        byte[] body = result.getBody();
        assert body != null;
        return body;
    }

    public void setPolicy(AzurePolicyConfiguration policy) {
        this.policy = policy;
    }

    public void setRestTemplate(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void setJsonHttpHeaders(HttpHeaders jsonHttpHeaders) {
        this.jsonHttpHeaders = jsonHttpHeaders;
    }

    public void setMetaDataClient(MetaDataClient metaDataClient) {
        this.metaDataClient = metaDataClient;
    }
}
