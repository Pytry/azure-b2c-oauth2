package com.dogjaw.services.authentication.b2c;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Created by Keith Hoopes on 2/25/2016.
 * Copyright Bear River Mutual 2016.
 */
public class AzureRsaKeys {

    @JsonProperty("keys")
    private List<RsaKeyB2C> keys;
    private String originalValue;

    public List<RsaKeyB2C> getKeys() {
        return keys;
    }

    public void setKeys(List<RsaKeyB2C> keys) {
        this.keys = keys;
    }

    public String getOriginalValue() {
        return originalValue;
    }

    public void setOriginalValue(String originalValue) {
        this.originalValue = originalValue;
    }
}
