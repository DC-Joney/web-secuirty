package com.security.starter.filter.interceptor;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.AbstractMethodSecurityMetadataSource;

import java.lang.reflect.Method;
import java.util.Collection;

public class PermissonAnnotationSecuirtyMetadataSource extends AbstractMethodSecurityMetadataSource {

    @Override
    public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }
}
