package com.security.starter.filter;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

public class QueryRequestMatcher implements RequestMatcher {

    private static final String DEFAULT_TOKEN_QUERY_NAME = "accessToken";

    private String tokenQueryName;

    private ServerProperties properties;

    public QueryRequestMatcher() {
        this(DEFAULT_TOKEN_QUERY_NAME);
    }

    public QueryRequestMatcher(String tokenQueryName) {
        this.tokenQueryName = tokenQueryName;

        if (!StringUtils.hasText(this.tokenQueryName)) {
            this.tokenQueryName = DEFAULT_TOKEN_QUERY_NAME;
        }
    }


    @Override
    public boolean matches(HttpServletRequest request) {

        Assert.notNull(getProperties(), () -> "The error path must be not null");

        try {
            return Optional.ofNullable(ServletRequestUtils.getStringParameter(request, tokenQueryName))
                    .map(StringUtils::hasText)
                    .filter(s -> !(request.getServletPath().equals(properties.getError().getPath())))
                    .orElse(false);
        } catch (ServletRequestBindingException e) {
            e.printStackTrace();
        }
        return false;
    }

    public void setProperties(ServerProperties properties) {
        this.properties = properties;
    }

    public ServerProperties getProperties() {
        return properties;
    }

    public void setTokenQueryName(String tokenQueryName) {
        this.tokenQueryName = tokenQueryName;
    }
}
