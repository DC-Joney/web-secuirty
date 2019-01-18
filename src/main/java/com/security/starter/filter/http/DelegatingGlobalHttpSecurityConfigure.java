package com.security.starter.filter.http;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Collections;
import java.util.List;
import java.util.Optional;


public class DelegatingGlobalHttpSecurityConfigure implements GlobalHttpSecurityConfigurer {

    private List<GlobalHttpSecurityConfigurer> filterConfigures;

    public DelegatingGlobalHttpSecurityConfigure(List<GlobalHttpSecurityConfigurer> securityFilterConfigures) {
        this.filterConfigures = securityFilterConfigures;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        List<GlobalHttpSecurityConfigurer> globalHttpSecurityConfigurers = Optional.ofNullable(filterConfigures).orElse(Collections.emptyList());

        for (GlobalHttpSecurityConfigurer configurer : globalHttpSecurityConfigurers) {
            configurer.configure(http);
        }
    }
}
