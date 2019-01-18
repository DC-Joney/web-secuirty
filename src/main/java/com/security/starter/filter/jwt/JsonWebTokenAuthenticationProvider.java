package com.security.starter.filter.jwt;

import com.security.starter.filter.QueryTokenAuthentication;
import com.security.starter.support.exception.JsonWebTokenError;
import com.security.starter.support.exception.JsonWebTokenErrorCodes;
import com.security.starter.support.exception.JwtAuthenticationException;
import com.security.starter.support.jwt.JWTAuthenticationConverter;
import com.security.starter.support.jwt.JWTAuthenticationConverterAdapter;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Objects;
import java.util.Optional;

public class JsonWebTokenAuthenticationProvider implements AuthenticationProvider {

    private final JwtDecoder jwtDecoder;

    private Converter<Jwt, ? extends Optional<Authentication>> jwtAuthenticationConverter
            = new JWTAuthenticationConverterAdapter(new JWTAuthenticationConverter());

    public JsonWebTokenAuthenticationProvider(JwtDecoder jwtDecoder){
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            if (!supports(authentication.getClass())) {
                return null;
            }
            QueryTokenAuthentication tokenAuthentication = (QueryTokenAuthentication) authentication;
            Jwt decode = jwtDecoder.decode(tokenAuthentication.getToken());

            return Objects.requireNonNull(jwtAuthenticationConverter.convert(decode))
                    .orElse(null);
        }catch (Exception e){

            JsonWebTokenError error = new JsonWebTokenError(JsonWebTokenErrorCodes.INVALID_TOKEN,
                    HttpStatus.UNAUTHORIZED,
                    e.getMessage());
            throw new JwtAuthenticationException(error);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (QueryTokenAuthentication.class.isAssignableFrom(authentication));
    }
}
