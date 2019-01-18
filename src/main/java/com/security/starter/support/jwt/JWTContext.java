package com.security.starter.support.jwt;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.util.Assert;

import java.util.List;

class JWTContext implements SecurityContext {

    private final List<JWK> jwkList;

    JWTContext(List<JWK> jwkList) {
        Assert.notNull(jwkList, "jwkList cannot be null");
        this.jwkList = jwkList;
    }

    public List<JWK> getJwkList() {
        return this.jwkList;
    }
}
