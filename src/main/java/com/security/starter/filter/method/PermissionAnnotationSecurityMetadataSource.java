package com.security.starter.filter.method;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.AbstractMethodSecurityMetadataSource;
import org.springframework.security.access.prepost.*;
import org.springframework.util.ClassUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class PermissionAnnotationSecurityMetadataSource extends AbstractMethodSecurityMetadataSource {

    private final PrePostInvocationAttributeFactory attributeFactory;

    public PermissionAnnotationSecurityMetadataSource(
            PrePostInvocationAttributeFactory attributeFactory) {
        this.attributeFactory = attributeFactory;
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {

        if (method.getDeclaringClass() == Object.class) {
            return Collections.emptyList();
        }

        logger.trace("Looking for Pre/Post annotations for method '" + method.getName()
                + "' on target class '" + targetClass + "'");
        PermissionAuthorize preAuthorize = findAnnotation(method, targetClass,
                PermissionAuthorize.class);

        if (preAuthorize == null ) {
            // There is no meta-data so return
            logger.trace("No expression annotations found");
            return Collections.emptyList();
        }

        String preFilterAttribute = preAuthorize.value();

        ArrayList<ConfigAttribute> attrs = new ArrayList<>(2);

        PreInvocationAttribute pre = attributeFactory.createPreInvocationAttribute(
                null, null, preFilterAttribute);

        if (pre != null) {
            attrs.add(pre);
        }

        attrs.trimToSize();

        return attrs;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    private <A extends Annotation> A findAnnotation(Method method, Class<?> targetClass,
                                                    Class<A> annotationClass) {
        // The method may be on an interface, but we need attributes from the target
        // class.
        // If the target class is null, the method will be unchanged.
        Method specificMethod = ClassUtils.getMostSpecificMethod(method, targetClass);
        A annotation = AnnotationUtils.findAnnotation(specificMethod, annotationClass);

        if (annotation != null) {
            logger.debug(annotation + " found on specific method: " + specificMethod);
            return annotation;
        }

        // Check the original (e.g. interface) method
        if (specificMethod != method) {
            annotation = AnnotationUtils.findAnnotation(method, annotationClass);

            if (annotation != null) {
                logger.debug(annotation + " found on: " + method);
                return annotation;
            }
        }

        // Check the class-level (note declaringClass, not targetClass, which may not
        // actually implement the method)
        annotation = AnnotationUtils.findAnnotation(specificMethod.getDeclaringClass(),
                annotationClass);

        if (annotation != null) {
            logger.debug(annotation + " found on: "
                    + specificMethod.getDeclaringClass().getName());
            return annotation;
        }

        return null;
    }


}
