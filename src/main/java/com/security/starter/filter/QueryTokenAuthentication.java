package com.security.starter.filter;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.util.Collections;

public class QueryTokenAuthentication extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private String token;

    public QueryTokenAuthentication(String token) {
        super(Collections.emptyList());

        Assert.hasText(token, "token cannot be empty");

        this.token = token;
    }


    public String getToken() {
        return this.token;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getCredentials() {
        return this.getToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getPrincipal() {
        return this.getToken();
    }
}
