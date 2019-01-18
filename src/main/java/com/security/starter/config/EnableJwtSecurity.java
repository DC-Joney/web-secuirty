package com.security.starter.config;

import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;


@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import(JsonWebTokenTypeRegister.class)
@ImportAutoConfiguration({WebSecurityMvcConfiguration.class
        , JWTConfiguration.class, GlobalMethodConfig.class})
public @interface EnableJwtSecurity {

    JsonWebTokenType type() default JsonWebTokenType.GLOBAL;

    enum JsonWebTokenType{
        GLOBAL,
        CUSTOM;
    }

}
