package com.security.starter.support.jwt;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;

import java.util.List;
import java.util.Optional;

public interface SecurityJWKSource {

    Optional<List<JWK>> get(JWKSelector jwkSelector);

}
