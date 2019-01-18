package com.security.starter.filter.http;

import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public interface HttpSecurityConfigurerCustomizer<T extends AbstractHttpConfigurer> {

    void customize(T configurer);
}
