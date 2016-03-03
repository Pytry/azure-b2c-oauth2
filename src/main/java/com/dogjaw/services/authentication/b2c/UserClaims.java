package com.dogjaw.services.authentication.b2c;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * Created by Keith Hoopes on 3/2/2016.
 * Copyright Bear River Mutual 2016.
 *
 * For holding OAuth2 claims retrieved from the content of a JWT.
 * Possibly for transforming into UserDetails, instead of
 * accessing the GraphAPI.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserClaims {//TODO: Extend UserDetails?

    //TODO: Add expected fields

    @JsonIgnore
    private Map<String, Object> additionalProperties;

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }
}
