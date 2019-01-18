package com.security.starter.support;

import com.security.starter.support.exception.JsonWebTokenError;
import com.security.starter.support.exception.JsonWebTokenErrorCodes;
import com.security.starter.support.exception.JwtAuthenticationException;
import org.springframework.http.HttpStatus;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.stream.Stream;

public class JsonWebTokenConverter implements TokenConverter {

    private boolean allowUriQueryParameter = false;

    /**
     * {@inheritDoc}
     */
    @Override
    public String convert(HttpServletRequest request) {
        String authorizationHeaderToken = null;
        String parameterToken = resolveFromRequestParameters(request);
        if (authorizationHeaderToken != null) {
            if (parameterToken != null) {
                JsonWebTokenError error = new JsonWebTokenError(JsonWebTokenErrorCodes.INVALID_REQUEST,
                        HttpStatus.BAD_REQUEST,
                        "Found multiple bearer tokens in the request");
                throw new JwtAuthenticationException(error);
            }
            return authorizationHeaderToken;
        }
        else if (parameterToken != null && isParameterTokenSupportedForRequest(request)) {
            return parameterToken;
        }
        return null;
    }

    public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
        this.allowUriQueryParameter = allowUriQueryParameter;
    }

    private static String resolveFromAuthorizationCookie(HttpServletRequest request) {
        Stream<Cookie> accessToken = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals("accessToken"));

        if(accessToken.count() != 1){

            JsonWebTokenError error = new JsonWebTokenError(JsonWebTokenErrorCodes.INVALID_REQUEST,
                    HttpStatus.BAD_REQUEST,
                    "The jwt token length is more than 1");

            throw new JwtAuthenticationException(error);
        }

        return  accessToken.findFirst().map(Cookie::getValue).orElse(null);

    }

    private static String resolveFromRequestParameters(HttpServletRequest request) {
        String[] values = request.getParameterValues("accessToken");

        if (values == null || values.length == 0)  {
            return null;
        }

        if (values.length == 1) {
            return values[0];
        }

        JsonWebTokenError error = new JsonWebTokenError(JsonWebTokenErrorCodes.INVALID_REQUEST,
                HttpStatus.BAD_REQUEST,
                "Found multiple bearer tokens in the request");
        throw new JwtAuthenticationException(error);
    }

    private boolean isParameterTokenSupportedForRequest(HttpServletRequest request) {
        return this.allowUriQueryParameter && "GET".equals(request.getMethod());
    }
}
