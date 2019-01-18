package com.security.starter.filter.jwt;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

import java.util.Collection;

public class JsonWebTokenAccessDecisionVoter implements AccessDecisionVoter {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return false;
    }

    @Override
    public boolean supports(Class clazz) {
        return false;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
        return 0;
    }
}
