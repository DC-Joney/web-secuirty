package com.security.starter.config;


import com.security.starter.filter.method.PermissionAnnotationSecurityMetadataSource;
import com.security.starter.filter.method.SecurityMethodSecurityExpressionHandler;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;

@Log4j2
@AutoConfigureAfter(JWTSecurityConfig.class)
public class GlobalMethodConfig {

    private ObjectProvider<MethodSecurityExpressionHandler> expressionHandler;

    public GlobalMethodConfig(@GlobalMethodSecurityMetadataSource
                                      ObjectProvider<MethodSecurityMetadataSource> metadataSource,
                              ObjectProvider<MethodSecurityExpressionHandler> expressionHandler) {

        this.expressionHandler = expressionHandler;

        log.info("=============================" + metadataSource.getIfAvailable());
        metadataSource.ifAvailable(source -> {
            if (source instanceof DelegatingMethodSecurityMetadataSource) {
                initMetadataSource((DelegatingMethodSecurityMetadataSource) source);
            }
        });
    }


    private void initMetadataSource(DelegatingMethodSecurityMetadataSource metadataSource) {
        expressionHandler.ifAvailable(handler->{
            ExpressionBasedAnnotationAttributeFactory attributeFactory = new ExpressionBasedAnnotationAttributeFactory(handler);
            PermissionAnnotationSecurityMetadataSource metadataSource1 = new PermissionAnnotationSecurityMetadataSource(attributeFactory);
            metadataSource.getMethodSecurityMetadataSources().add(metadataSource1);
        });
        log.info(metadataSource.getMethodSecurityMetadataSources());
//        metadataSource.getMethodSecurityMetadataSources().add();
    }
}
