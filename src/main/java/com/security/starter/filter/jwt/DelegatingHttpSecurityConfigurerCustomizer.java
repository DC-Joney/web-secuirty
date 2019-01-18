package com.security.starter.filter.jwt;

import com.security.starter.filter.HttpSecurityConfigurerCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.List;
import java.util.Optional;


public class DelegatingHttpSecurityConfigurerCustomizer<T extends AbstractHttpConfigurer>
        implements HttpSecurityConfigurerCustomizer<T> {

    private List<HttpSecurityConfigurerCustomizer<T>> customizers;

    public DelegatingHttpSecurityConfigurerCustomizer(List<HttpSecurityConfigurerCustomizer<T>> customizers){
        this.customizers = customizers;
    }

    @Override
    public void customize(T configurer) {
        Optional.ofNullable(customizers)
                .ifPresent(configures-> configures.forEach(configure-> configure.customize(configurer)));
    }
}
