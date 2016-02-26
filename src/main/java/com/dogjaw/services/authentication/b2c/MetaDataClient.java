package com.dogjaw.services.authentication.b2c;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import static org.springframework.http.HttpMethod.GET;

/**
 * Created by Keith Hoopes on 2/25/2016.
 * Copyright Bear River Mutual 2016.
 */
public class MetaDataClient {

    private AzurePolicyConfiguration policy;

    private RestTemplate restTemplate;

    private HttpHeaders jsonHttpHeaders;

    /**
     * Retrieves the meta data for the signin policy.
     * Since the meta data is not likely to change,
     * the cache is not set to expire.
     *
     * @return {@link AzurePolicyMetaData}
     */
    public AzurePolicyMetaData getSigninMetaData() {

        return getAzurePolicyMetaData(policy.getSigninPolicy());
    }

    /**
     * Retrieves the meta data for the signup policy.
     * Since the meta data is not likely to change,
     * the cache is not set to expire.
     *
     * @return {@link AzurePolicyMetaData}
     */
    public AzurePolicyMetaData getSignupMetaData() {

        return getAzurePolicyMetaData(policy.getSignupPolicy());
    }

    /**
     * Retrieves the meta data for the signup policy.
     * Since the meta data is not likely to change,
     * the cache is not set to expire.
     *
     * @return {@link AzurePolicyMetaData}
     */
    public AzurePolicyMetaData getEditProfileMetaData() {

        return getAzurePolicyMetaData(policy.getEditProfilePolicy());
    }

    /**
     * Retrieves the meta-data for the given policy name.
     *
     * @param policyName Name of the b2c policy.
     * @return {@link AzurePolicyMetaData}
     */
    private AzurePolicyMetaData getAzurePolicyMetaData(String policyName) {

        assert jsonHttpHeaders != null;
        assert restTemplate != null;
        assert policyName != null;

        String wellknownUrl = toPolicyUrl(policy.getWellknownUrl(), policyName);
        assert wellknownUrl != null && !"".equals(wellknownUrl.trim());

        HttpEntity<AzurePolicyMetaData> requestEntity = new HttpEntity<>(jsonHttpHeaders);

        ResponseEntity<AzurePolicyMetaData> result = restTemplate.exchange(
                wellknownUrl, GET, requestEntity, AzurePolicyMetaData.class);

        AzurePolicyMetaData body = result.getBody();
        assert body != null;

        return body;
    }

    private String toPolicyUrl(String url, String policyName) {

        return url + "?p=" + policyName;
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
}
