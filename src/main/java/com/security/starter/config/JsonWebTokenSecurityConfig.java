package com.security.starter.config;

import com.security.starter.filter.http.GlobalHttpSecurityConfigurer;
import com.security.starter.filter.http.HttpSecurityConfigurerCustomizer;
import com.security.starter.filter.http.SecurityFilterConfigure;
import com.security.starter.filter.jwt.JsonWebTokenSecurityConfigurer;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

@Log4j2
@AutoConfigureAfter({JWTConfiguration.class})
public class JsonWebTokenSecurityConfig implements GlobalHttpSecurityConfigurer, ApplicationContextAware {

    private ApplicationContext applicationContext;

    private ServerProperties properties;

    @Autowired(required = false)
    private SecurityFilterConfigure securityFilterConfigure;

    @Autowired(required = false)
    private HttpSecurityConfigurerCustomizer<AbstractHttpConfigurer> configurerCustomizer;


    public JsonWebTokenSecurityConfig(@GlobalMethodSecurityMetadataSource ObjectProvider<MethodSecurityMetadataSource> metadataSource,
                                      ServerProperties properties) {

        this.properties = properties;
        log.info("=============================" + metadataSource.getIfAvailable());
        metadataSource.ifAvailable(source -> {
            if (source instanceof DelegatingMethodSecurityMetadataSource) {
                initMetadataSource((DelegatingMethodSecurityMetadataSource) source);
            }
        });
    }


    private void initMetadataSource(DelegatingMethodSecurityMetadataSource metadataSource) {
        log.info(metadataSource.getMethodSecurityMetadataSources());
//        metadataSource.getMethodSecurityMetadataSources().add();
    }


    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        JsonWebTokenSecurityConfigurer securityConfigurer = getSingleBeanOrNull(JsonWebTokenConfig.JSON_WEB_TOKEN_SECURITY_CONFIGURER, JsonWebTokenSecurityConfigurer.class);;

        AuthenticationFailureHandler failureHandler = getSingleBeanOrNull(JsonWebTokenConfig.FAIL_HANDLER_BEAN_NAME, AuthenticationFailureHandler.class);

        AuthenticationSuccessHandler successHandler = getSingleBeanOrNull(JsonWebTokenConfig.SUCCESS_HANDLER_BEAN_NAME, AuthenticationSuccessHandler.class);

        http.setSharedObject(AuthenticationFailureHandler.class, failureHandler);

        http.setSharedObject(AuthenticationSuccessHandler.class, successHandler);

        securityFilterConfigure.configure(http);

        configurerCustomizer.customize(securityConfigurer);

        Assert.notNull(securityConfigurer,()-> "The JsonWebTokenSecurityConfigurer must not be null");

        http.apply(securityConfigurer)
            .and().authorizeRequests().antMatchers(properties.getError().getPath()).permitAll();
    }

    private <T> T getSingleBeanOrNull(String beanName, Class<T> type) {
        try {
            return applicationContext.getBean(beanName, type);
        } catch (NoSuchBeanDefinitionException e) {
            log.info(e);
        }
        return null;
    }



    //    @Bean
//    public ErrorPageRegistrar deleteDefaultErrorPage(DispatcherServletPath servletPath){
//        return registry -> {
//            ErrorPage errorPage = new ErrorPage(AuthenticationException.class,null);
//            registry.addErrorPages(errorPage);
//            log.info(registry);
//            log.info(servletPath);
//        };
//    }



}
