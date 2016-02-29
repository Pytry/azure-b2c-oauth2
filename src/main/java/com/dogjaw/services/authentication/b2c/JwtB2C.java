package com.dogjaw.services.authentication.b2c;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;

import java.io.IOException;
import java.util.LinkedHashMap;

/**
 * Created by Keith Hoopes on 2/29/2016.
 * Copyright Bear River Mutual 2016.
 */
public class JwtB2C implements Jwt {

    private final Jwt jwt;
    private final JwtHeader header;

    public JwtB2C(Jwt jwt) throws IOException {

        this.jwt = jwt;
        this.header = new JwtHeader(jwt);

    }

    public JwtHeader getHeader(){

        return header;
    }
    @Override
    public String getClaims() {

        return jwt.getClaims();
    }

    @Override
    public String getEncoded() {

        return jwt.getEncoded();
    }

    @Override
    public void verifySignature(SignatureVerifier verifier) {

        jwt.verifySignature(verifier);
    }

    @Override
    public byte[] bytes() {

        return jwt.bytes();
    }

    @SuppressWarnings("unchecked")
    public final static class JwtHeader{

        private final LinkedHashMap<String, String> value;
        private JwtHeader(Jwt jwt) throws IOException {

            String json = jwt.toString();
            value = (LinkedHashMap<String, String>)(new ObjectMapper()).readValue(json, LinkedHashMap.class);
        }

        public String getTyp(){

            return value.get("typ");
        }
        public String getAlg(){

            return value.get("alg");
        }
        public String getKid(){

            return value.get("kid");
        }
    }
}
