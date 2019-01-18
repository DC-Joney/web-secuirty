package com.security.starter.support.exception;


import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

public class JwtAuthenticationException extends AuthenticationException {

    private JsonWebTokenError error;

    public JwtAuthenticationException(JsonWebTokenError error) {
        this(error, error.getDescription());
    }

    public JwtAuthenticationException(JsonWebTokenError error, Throwable cause) {
        this(error, cause.getMessage(), cause);
    }

    public JwtAuthenticationException(JsonWebTokenError error, String message) {
        super(message);
        this.setError(error);
    }


    public JwtAuthenticationException(JsonWebTokenError error, String message, Throwable cause) {
        super(message, cause);
        this.setError(error);
    }

    public JsonWebTokenError getError() {
        return this.error;
    }

    private void setError(JsonWebTokenError error) {
        Assert.notNull(error, "error cannot be null");
        this.error = error;
    }
}
