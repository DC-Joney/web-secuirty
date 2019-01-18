package com.security.starter.filter.method;

import java.lang.annotation.*;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface PermissionAuthorize {

    /**
     * @return the Spring-EL expression to be evaluated before invoking the protected
     * method
     */
    String value();
}
