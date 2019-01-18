package com.security.starter.config;

import org.springframework.beans.factory.annotation.Qualifier;

import java.lang.annotation.*;

@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Qualifier(value = JsonWebTokenConfig.REQUEST_PATH_MATCHER)
public @interface TokenRequestMatcher {


}
