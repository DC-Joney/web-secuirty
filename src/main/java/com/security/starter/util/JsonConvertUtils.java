package com.security.starter.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.security.starter.support.RSAKeyPair;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;

public abstract class JsonConvertUtils {

    private static ConversionService conversionService;

    static {
        conversionService = DefaultConversionService.getSharedInstance();
    }

    public static <T> String convertToString(T obj) {

        Assert.notNull(obj, "Convert obj must not be null");

        return conversionService.convert(obj, String.class);
    }


    public static <T extends Authentication> String convertToJWtString(T obj, RSAKeyPair rsaKeyPair) {

        Assert.notNull(obj, "Convert obj must not be null");

        try {
            Instant instant = Instant.now(Clock.systemUTC()).minus(Duration.ofSeconds(60));
            JWTClaimsSet joe = new JWTClaimsSet.Builder()
                    .subject(obj.getName())
                    .audience("BROWSER")
                    .issueTime(Date.from(instant))
                    .expirationTime(Date.from(instant.plus(Duration.ofMinutes(60))))
                    .claim("http://example.com/is_root", true)
                    .claim("username",obj.getName())
                    .claim("authorities", computedAuthorize(obj.getAuthorities()))
                    .claim("password", obj.getCredentials())
                    .build();


            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .contentType("text/plain")
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, joe);

            RSASSASigner rsassaSigner = new RSASSASigner(rsaKeyPair.getPrivateKey());

            signedJWT.sign(rsassaSigner);

            return signedJWT.serialize();

        } catch (JOSEException e) {
            e.printStackTrace();
        }

        return null;


    }


    private static String computedAuthorize(Collection<? extends GrantedAuthority> authorities){
        return authorities
                .stream()
                .map(GrantedAuthority::getAuthority)
                .reduce((pre, post) -> pre + "," +post)
                .orElse("ROLE_ANONYMOUS");
    }


}
