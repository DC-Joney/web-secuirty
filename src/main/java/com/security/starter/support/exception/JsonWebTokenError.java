package com.security.starter.support.exception;

import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

@Data
public class JsonWebTokenError {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final String errorCode;

    private final String description;

    private final HttpStatus httpStatus;

    public JsonWebTokenError(String errorCode, HttpStatus httpStatus ,String description) {
        Assert.hasText(errorCode, "errorCode cannot be empty");
        this.errorCode = errorCode;
        this.description = description;
        this.httpStatus = httpStatus;
    }


    public JsonWebTokenError(JsonWebTokenError tokenError) {
        Assert.notNull(tokenError, ()-> "tokenError cannot be empty");
        Assert.hasText(tokenError.getErrorCode(), ()-> "tokenError cannot be empty");
        this.errorCode = tokenError.getErrorCode();
        this.description = tokenError.getDescription();
        this.httpStatus = tokenError.getHttpStatus();
    }



}
