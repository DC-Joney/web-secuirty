package com.security.starter.support.jwt;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.List;
import java.util.Optional;

class JWKSourceAdapter implements SecurityJWKSource{

    private final JWKSource<SecurityContext> source;

    JWKSourceAdapter(JWKSource<SecurityContext> source) {
        this.source = source;
    }

    @Override
    public Optional<List<JWK>> get(JWKSelector jwkSelector){
        try {
            return Optional.ofNullable(this.source.get(jwkSelector, null));
        } catch (KeySourceException e) {
            throw  new IllegalStateException("Could not obtain the keys",e);
        }
    }

}
