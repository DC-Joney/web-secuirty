package com.security.starter.support.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.Assert;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class NimbusSecuirtyJwtDecoder implements JwtDecoder {
    private final JWTProcessor<JWTContext> jwtProcessor;

    private final SecurityJWKSource jwkSource;

    private final JWKSelectorFactory jwkSelectorFactory;

    private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();

    public NimbusSecuirtyJwtDecoder(RSAPublicKey publicKey) {
        JWSAlgorithm algorithm = JWSAlgorithm.parse(JwsAlgorithms.RS256);

        RSAKey rsaKey = rsaKey(publicKey);
        JWKSet jwkSet = new JWKSet(rsaKey);
        JWKSource jwkSource = new ImmutableJWKSet<>(jwkSet);
        JWSKeySelector<JWTContext> jwsKeySelector =
                new JWSVerificationKeySelector<>(algorithm, jwkSource);
        DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});

        this.jwtProcessor = jwtProcessor;
        this.jwkSource = new JWKSourceAdapter(jwkSource);
        this.jwkSelectorFactory = new JWKSelectorFactory(algorithm);
    }

//    /**
//     * Constructs a {@code NimbusJwtDecoderJwkSupport} using the provided parameters.
//     *
//     * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
//     */
//    public SpringNimbusJwtDecoder(String jwkSetUrl) {
//        Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");
//        String jwsAlgorithm = JwsAlgorithms.RS256;
//        JWSAlgorithm algorithm = JWSAlgorithm.parse(jwsAlgorithm);
//        JWKSource jwkSource = new JWKContextJWKSource();
//        JWSKeySelector<JWKContext> jwsKeySelector =
//                new JWSVerificationKeySelector<>(algorithm, jwkSource);
//
//        DefaultJWTProcessor<JWKContext> jwtProcessor = new DefaultJWTProcessor<>();
//        jwtProcessor.setJWSKeySelector(jwsKeySelector);
//        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});
//        this.jwtProcessor = jwtProcessor;
//
//        this.reactiveJwkSource = new RemoteJ(jwkSetUrl);
//
//        this.jwkSelectorFactory = new JWKSelectorFactory(algorithm);
//
//    }

    /**
     * Use the provided {@link OAuth2TokenValidator} to validate incoming {@link Jwt}s.
     *
     * @param jwtValidator the {@link OAuth2TokenValidator} to use
     */
    public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
        Assert.notNull(jwtValidator, "jwtValidator cannot be null");
        this.jwtValidator = jwtValidator;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        JWT jwt = parse(token);
        if (jwt instanceof SignedJWT) {
            return this.decode((SignedJWT) jwt);
        }
        throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
    }

    private JWT parse(String token) {
        try {
            return JWTParser.parse(token);
        } catch (Exception ex) {
            throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
        }
    }

    private Jwt decode(SignedJWT parsedToken) {
        try {
            JWKSelector selector = this.jwkSelectorFactory
                    .createSelector(parsedToken.getHeader());

            return this.jwkSource.get(selector)
                    .map(jwkList -> createClaimsSet(parsedToken, jwkList))
                    .map(set -> createJwt(parsedToken, set))
                    .map(this::validateJwt)
                    .orElseThrow(()-> new JwtException("An error occurred while attempting to decode the Jwt"));

        } catch (RuntimeException e) {
            throw new JwtException("An error occurred while attempting to decode the Jwt: " + e.getMessage(), e);
        }
    }

    private JWTClaimsSet createClaimsSet(JWT parsedToken, List<JWK> jwkList) {
        try {
            return this.jwtProcessor.process(parsedToken, new JWTContext(jwkList));
        }
        catch (BadJOSEException | JOSEException e) {
            throw new JwtException("Failed to validate the token", e);
        }
    }

    private Jwt createJwt(JWT parsedJwt, JWTClaimsSet jwtClaimsSet) {
        Instant expiresAt = null;
        if (jwtClaimsSet.getExpirationTime() != null) {
            expiresAt = jwtClaimsSet.getExpirationTime().toInstant();
        }
        Instant issuedAt = null;
        if (jwtClaimsSet.getIssueTime() != null) {
            issuedAt = jwtClaimsSet.getIssueTime().toInstant();
        } else if (expiresAt != null) {
            // Default to expiresAt - 1 second
            issuedAt = Instant.from(expiresAt).minusSeconds(1);
        }

        Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());

        return new Jwt(parsedJwt.getParsedString(), issuedAt, expiresAt, headers, jwtClaimsSet.getClaims());
    }

    private Jwt validateJwt(Jwt jwt) {
        OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);

        if ( result.hasErrors() ) {
            String message = result.getErrors().iterator().next().getDescription();
            throw new JwtValidationException(message, result.getErrors());
        }

        return jwt;
    }

    private static RSAKey rsaKey(RSAPublicKey publicKey) {
        return new RSAKey.Builder(publicKey)
                .build();
    }
}
