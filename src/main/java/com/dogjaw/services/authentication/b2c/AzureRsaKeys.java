package com.dogjaw.services.authentication.b2c;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;

import java.util.List;

/**
 * Created by Keith Hoopes on 2/25/2016.
 *
 */
public class AzureRsaKeys {

    @JsonProperty("keys")
    private List<RsaKeyB2C> keys;

    @JsonGetter("keys")
    public List<RsaKeyB2C> getKeys() {
        return keys;
    }

    @JsonSetter("keys")
    public void setKeys(List<RsaKeyB2C> keys) {
        this.keys = keys;
    }
}
