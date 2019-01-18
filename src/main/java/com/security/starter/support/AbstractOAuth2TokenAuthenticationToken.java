package com.security.starter.support;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Map;

public abstract class AbstractOAuth2TokenAuthenticationToken<T extends AbstractOAuth2Token> extends AbstractAuthenticationToken {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private T token;

    /**
     * Sub-class constructor.
     */
    protected AbstractOAuth2TokenAuthenticationToken(T token) {

        this(token, null);
    }

    /**
     * Sub-class constructor.
     *
     * @param authorities the authorities assigned to the Access Token
     */
    protected AbstractOAuth2TokenAuthenticationToken(
            T token,
            Collection<? extends GrantedAuthority> authorities) {

        super(authorities);

        Assert.notNull(token, "token cannot be null");
        this.token = token;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getPrincipal() {
        return this.getToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getCredentials() {
        return this.getToken();
    }

    /**
     * Get the token bound to this {@link Authentication}.
     */
    public final T getToken() {
        return this.token;
    }

    /**
     * Returns the attributes of the access token.
     *
     * @return a {@code Map} of the attributes in the access token.
     */
    public abstract Map<String, Object> getTokenAttributes();
}
