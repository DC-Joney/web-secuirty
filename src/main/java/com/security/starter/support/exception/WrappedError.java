package com.security.starter.support.exception;

import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
public class WrappedError implements Serializable {
    private Date timestamp;
    private int status;
    private String error;
    private String message;
    private String path;

    public WrappedError(JsonWebTokenError tokenError,String path){
        this.timestamp = new Date();
        this.status = tokenError.getHttpStatus().value();
        this.error = tokenError.getHttpStatus().getReasonPhrase();
        this.message = tokenError.getDescription();
        this.path = path;
    }

}
