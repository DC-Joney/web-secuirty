package com.security.starter.config;


import com.security.starter.properties.JsonWebTokenProperties;
import com.security.starter.support.AbstractOAuth2TokenAuthenticationToken;
import com.security.starter.support.converter.TokenErrorConverter;
import com.security.starter.support.converter.ObjectToJsonStringConverter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ApplicationContextEvent;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.convert.support.DefaultConversionService;

import java.util.Optional;

@Log4j2
@AutoConfigureAfter(JWTConfiguration.class)
@ConditionalOnClass({JsonWebTokenProperties.class, AbstractOAuth2TokenAuthenticationToken.class})
class WebSecurityMvcConfiguration implements ApplicationContextAware, ApplicationListener<ContextRefreshedEvent>, InitializingBean {

    private ConverterRegistry converterRegistry;

    private ApplicationContext applicationContext;

    @Override
    public void afterPropertiesSet(){
        this.converterRegistry = (ConverterRegistry) DefaultConversionService.getSharedInstance();
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        Optional.of(event)
                .map(ApplicationContextEvent::getApplicationContext)
                .filter(context-> context == applicationContext)
                .flatMap(context-> Optional.ofNullable(converterRegistry))
                .ifPresent(registry-> {
                    registry.addConverter(new ObjectToJsonStringConverter());
                    registry.addConverter(new TokenErrorConverter());
                });
    }

}

