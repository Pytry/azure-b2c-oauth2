package com.dogjaw.services.authentication.tokens;

import org.springframework.security.jwt.crypto.sign.SignatureVerifier;

/**
 * Created by Keith Hoopes on 2/24/2016.
 * Copyright Bear River Mutual 2016.
 */
public class AzureJwtVerifier implements SignatureVerifier {
    @Override
    public void verify(byte[] content, byte[] signature) {

    }

    @Override
    public String algorithm() {
        return "SHA256";
    }
}
