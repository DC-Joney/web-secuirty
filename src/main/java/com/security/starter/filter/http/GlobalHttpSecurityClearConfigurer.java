package com.security.starter.filter.http;

import com.security.starter.config.TokenRequestMatcher;
import com.security.starter.filter.SecurityClearContextFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class GlobalHttpSecurityClearConfigurer implements GlobalHttpSecurityConfigurer {


    private RequestMatcher requestMatcher;

    public GlobalHttpSecurityClearConfigurer(@TokenRequestMatcher RequestMatcher requestMatcher){
        this.requestMatcher = requestMatcher;
    }

    @Override
    public void configure(HttpSecurity http) {

        SecurityClearContextFilter clearContextFilter = new SecurityClearContextFilter(http.getSharedObject(SecurityContextRepository.class),requestMatcher);

        http.setSharedObject(SecurityClearContextFilter.class,clearContextFilter);

        http.addFilterAfter(clearContextFilter, SecurityContextPersistenceFilter.class);

        http.setSharedObject(RequestMatcher.class, requestMatcher);

    }


}
