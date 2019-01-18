package com.security.starter.config;

import org.springframework.beans.factory.annotation.Qualifier;

import java.lang.annotation.*;

@Target({ ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE,
        ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Qualifier(value = GlobalMethodSecurityMetadataSource.VALUE)
public @interface GlobalMethodSecurityMetadataSource {
    String VALUE = "methodSecurityMetadataSource";

}
