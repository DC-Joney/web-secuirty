package com.security.starter.config;

import org.springframework.boot.autoconfigure.ImportAutoConfiguration;

import java.lang.annotation.*;


@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@ImportAutoConfiguration({WebSecurityMvcConfiguration.class
        , JWTConfiguration.class,JsonWebTokenSecurityConfig.class})
public @interface EnableJwtSecurity {

}
