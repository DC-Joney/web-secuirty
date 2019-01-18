package com.security.starter.filter;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;
import java.util.Optional;


public class DelegatingSecurityFilterConfigure implements SecurityFilterConfigure{

    private List<SecurityFilterConfigure> filterConfigures;

    public DelegatingSecurityFilterConfigure(List<SecurityFilterConfigure> securityFilterConfigures){
        this.filterConfigures = securityFilterConfigures;
    }

    @Override
    public void configure(HttpSecurity http) {
        Optional.ofNullable(filterConfigures)
                .ifPresent(configures-> configures.forEach(configure-> configure.configure(http)));
    }
}
