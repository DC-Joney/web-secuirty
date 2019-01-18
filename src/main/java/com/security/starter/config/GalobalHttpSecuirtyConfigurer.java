package com.security.starter.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.stereotype.Component;

@Component
@Log4j2
@Order(20)
public class GalobalHttpSecuirtyConfigurer extends AbstractHttpConfigurer<GalobalHttpSecuirtyConfigurer, HttpSecurity> {

    public GalobalHttpSecuirtyConfigurer(){
       log.info("11111");
           }

    @Override
    public void init(HttpSecurity builder) throws Exception {
//        WebSecurity webSecurity;
//        webSecurity.apply()
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        super.configure(builder);
    }
}
