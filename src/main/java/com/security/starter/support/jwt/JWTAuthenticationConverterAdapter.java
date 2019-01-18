package com.security.starter.support.jwt;

import com.security.starter.support.JsonWebAuthenticationToken;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.util.Optional;

public class JWTAuthenticationConverterAdapter implements Converter<Jwt, Optional<Authentication>> {

    private final JWTAuthenticationConverter delegate;

    public JWTAuthenticationConverterAdapter(JWTAuthenticationConverter delegate) {
        Assert.notNull(delegate, "delegate cannot be null");
        this.delegate = delegate;
    }

    public final Optional<Authentication> convert(Jwt jwt) {
        return Optional.ofNullable(jwt)
                .map(this.delegate::convert)
                .map(this::repackageToken);
    }

    private Authentication repackageToken(AbstractAuthenticationToken authenticationToken) {

        JsonWebAuthenticationToken token = (JsonWebAuthenticationToken) authenticationToken;

        String authorities = (String) token.getToken()
                .getClaims().getOrDefault("authorities", "ROLE_ANONYMOUS");

        return new JsonWebAuthenticationToken(token.getToken(), AuthorityUtils.createAuthorityList(authorities.split(",")));

    }


}
