package com.security.starter.filter;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;

public class SecurityClearConfigure implements SecurityFilterConfigure {

    @Override
    public void configure(HttpSecurity http) {

        QueryRequestMatcher requestMatcher = http.getSharedObject(QueryRequestMatcher.class);

        SecurityClearContextFilter clearContextFilter = new SecurityClearContextFilter(http.getSharedObject(SecurityContextRepository.class),requestMatcher);

        http.setSharedObject(SecurityClearContextFilter.class,clearContextFilter);

        http.addFilterAfter(clearContextFilter,SecurityContextPersistenceFilter.class);
    }


}
