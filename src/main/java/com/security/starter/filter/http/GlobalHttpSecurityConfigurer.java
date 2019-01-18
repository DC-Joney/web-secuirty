package com.security.starter.filter.http;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface GlobalHttpSecurityConfigurer {

    void configure(HttpSecurity http) throws Exception;

}
