package com.security.starter.config;

import com.security.starter.filter.http.GlobalHttpSecurityConfigurer;
import com.security.starter.filter.http.HttpSecurityConfigurerCustomizer;
import com.security.starter.filter.http.SecurityFilterConfigure;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

@Log4j2
public class JWTSecurityConfig implements GlobalHttpSecurityConfigurer, ApplicationContextAware {

    private ApplicationContext applicationContext;

    private ServerProperties properties;

    @Autowired(required = false)
    private SecurityFilterConfigure securityFilterConfigure;

    @Autowired(required = false)
    private HttpSecurityConfigurerCustomizer<AbstractHttpConfigurer> configurerCustomizer;

    public JWTSecurityConfig(ServerProperties properties) {
        this.properties = properties;
    }


    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        com.security.starter.filter.jwt.JsonWebTokenSecurityConfigurer securityConfigurer = getSingleBeanOrNull(JsonWebTokenConfig.JSON_WEB_TOKEN_SECURITY_HTTP_CONFIGURER, com.security.starter.filter.jwt.JsonWebTokenSecurityConfigurer.class);;

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
