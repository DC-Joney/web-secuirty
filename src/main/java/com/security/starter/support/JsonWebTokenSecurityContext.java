package com.security.starter.support;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.util.Assert;

public class JsonWebTokenSecurityContext extends SecurityContextImpl {

    private String tokenCode;

    public JsonWebTokenSecurityContext(String tokenCode, Authentication authentication) {
        super(authentication);
        Assert.hasText(tokenCode,"The jwt code must not be null");
        this.tokenCode = tokenCode;
    }

    public String getTokenCode() {
        return tokenCode;
    }

    public void setTokenCode(String tokenCode) {
        this.tokenCode = tokenCode;
    }

    @Override
    public String toString() {
        return super.toString() + "tokenCode : " + tokenCode;
    }
}
