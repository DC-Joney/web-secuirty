package com.security.starter.support.jwt;

import com.security.starter.support.JsonWebAuthenticationToken;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

public class JWTAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final String SCOPE_AUTHORITY_PREFIX = "SCOPE_";

    private static final Collection<String> WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES =
            Arrays.asList("scope", "scp");


    public final AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        return new JsonWebAuthenticationToken(jwt, authorities);
    }

    protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        return this.getScopes(jwt)
                .stream()
                .map(authority -> SCOPE_AUTHORITY_PREFIX + authority)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private Collection<String> getScopes(Jwt jwt) {
        for ( String attributeName : WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES ) {
            Object scopes = jwt.getClaims().get(attributeName);
            if (scopes instanceof String) {
                if (StringUtils.hasText((String) scopes)) {
                    return Arrays.asList(((String) scopes).split(" "));
                } else {
                    return Collections.emptyList();
                }
            } else if (scopes instanceof Collection) {
                return (Collection<String>) scopes;
            }
        }

        return Collections.emptyList();
    }
}
