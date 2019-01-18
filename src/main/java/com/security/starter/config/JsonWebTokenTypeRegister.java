package com.security.starter.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.type.AnnotationMetadata;

import java.util.Map;

@Log4j2
public class JsonWebTokenTypeRegister implements ImportBeanDefinitionRegistrar {

    private static final String DEFAULT_ATTRIBUTES_NAME = "type";

    @Override
    public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
        Map<String, Object> annotationAttributes =
                importingClassMetadata.getAnnotationAttributes(EnableJwtSecurity.class.getName());


        EnableJwtSecurity.JsonWebTokenType requestMode = (annotationAttributes == null
                ?  (EnableJwtSecurity.JsonWebTokenType) AnnotationUtils.getDefaultValue(EnableJwtSecurity.class,DEFAULT_ATTRIBUTES_NAME)
                : (EnableJwtSecurity.JsonWebTokenType) annotationAttributes.get(DEFAULT_ATTRIBUTES_NAME));


        assert requestMode != null;

        if (!registry.containsBeanDefinition(JsonWebTokenConfig.JSON_WEB_TOKEN_SECURITY_GLOBAL_CONFIGURER) && requestMode.equals(EnableJwtSecurity.JsonWebTokenType.GLOBAL)) {
            BeanDefinitionBuilder builder =
                    BeanDefinitionBuilder.genericBeanDefinition(JWTSecurityConfig.class)
                            .setRole(BeanDefinition.ROLE_INFRASTRUCTURE).setAutowireMode(AbstractBeanDefinition.AUTOWIRE_CONSTRUCTOR);

            BeanDefinition beanDefinition = builder.getBeanDefinition();
            registry.registerBeanDefinition(JsonWebTokenConfig.JSON_WEB_TOKEN_SECURITY_GLOBAL_CONFIGURER,
                    beanDefinition);
        }
    }
}
