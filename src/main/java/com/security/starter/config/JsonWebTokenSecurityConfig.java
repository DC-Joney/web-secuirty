package com.security.starter.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.security.starter.filter.*;
import com.security.starter.filter.jwt.DelegatingHttpSecurityConfigurerCustomizer;
import com.security.starter.filter.jwt.JsonWebTokenSecurityConfigurer;
import com.security.starter.filter.jwt.JsonWebTokenSecurityConfigurerCustomizer;
import com.security.starter.properties.JsonWebTokenProperties;
import com.security.starter.service.DemoService;
import com.security.starter.support.strategy.JsonStrategy;
import com.security.starter.support.RSAKeyPair;
import com.security.starter.support.SecurityMethodSecurityExpressionHandler;
import com.security.starter.support.handler.JsonServerAuthenticationFailureHandler;
import com.security.starter.support.handler.JsonServerAuthenticationSuccessHandler;
import com.security.starter.support.strategy.DefaultJsonStrategy;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

@Log4j2
@ConditionalOnClass(AuthenticationConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@AutoConfigureAfter(AuthenticationConfiguration.class)
@AutoConfigureBefore(ErrorMvcAutoConfiguration.class)
@EnableConfigurationProperties(JsonWebTokenProperties.class)
public class JsonWebTokenSecurityConfig extends WebSecurityConfigurerAdapter {

    private RSAKeyPair rsaKeyPair;

    @Autowired(required = false)
    private SecurityFilterConfigure securityFilterConfigure;


    @Autowired(required = false)
    private HttpSecurityConfigurerCustomizer<AbstractHttpConfigurer> configurerCustomizer;


    public JsonWebTokenSecurityConfig(RSAKeyPair rsaKeyPair,
                                      @GlobalMethodSecurityMetadataSource ObjectProvider<MethodSecurityMetadataSource> metadataSource) {

        this.rsaKeyPair = rsaKeyPair;
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


//    @Bean
//    public ErrorPageRegistrar deleteDefaultErrorPage(DispatcherServletPath servletPath){
//        return registry -> {
//            ErrorPage errorPage = new ErrorPage(AuthenticationException.class,null);
//            registry.addErrorPages(errorPage);
//            log.info(registry);
//            log.info(servletPath);
//        };
//    }




    @Override
    protected void configure(HttpSecurity http) throws Exception {

        JsonWebTokenSecurityConfigurer<HttpSecurity> securityConfigurer = new JsonWebTokenSecurityConfigurer<>(rsaKeyPair);

        QueryRequestMatcher requestMatcher = getSingleBeanOrNull(JsonWebTokenConfig.REQUEST_PATH_MATCHER, QueryRequestMatcher.class);

        http.setSharedObject(QueryRequestMatcher.class, requestMatcher);

        AuthenticationFailureHandler failureHandler = getSingleBeanOrNull(JsonWebTokenConfig.FAIL_HANDLER_BEAN_NAME, AuthenticationFailureHandler.class);

        AuthenticationSuccessHandler successHandler = getSingleBeanOrNull(JsonWebTokenConfig.SUCCESS_HANDLER_BEAN_NAME, AuthenticationSuccessHandler.class);

        http.setSharedObject(AuthenticationFailureHandler.class, failureHandler);

        http.setSharedObject(AuthenticationSuccessHandler.class, successHandler);

        securityFilterConfigure.configure(http);

        configurerCustomizer.customize(securityConfigurer);

        http.apply(securityConfigurer)
            .and()
            .requestMatchers()
            .requestMatchers(requestMatcher);
    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }


    private <T> T getSingleBeanOrNull(String beanName, Class<T> type) {
        try {
            return getApplicationContext().getBean(beanName, type);
        } catch (NoSuchBeanDefinitionException e) {
        }
        return null;
    }


    @Configuration
    @ConditionalOnMissingBean(RSAKeyPair.class)
    @ConditionalOnClass({Jwt.class, JWTClaimsSet.class})
    public static class JWTConfiguration {

        private ObjectProvider<ExceptionHandler> exceptionHandler;

        public JWTConfiguration(ObjectProvider<ExceptionHandler> exceptionHandler) {
            this.exceptionHandler = exceptionHandler;
        }

        @Lazy
        @Bean
        @ConditionalOnMissingBean
        public RSAKeyPair rsaKeyPair() {
            try {
                //实例化密钥生成器
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                //初始化密钥生成器
                keyPairGenerator.initialize(1024);
                //生成密钥对
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                //甲方公钥
                RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
                //甲方私钥
                RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
                return RSAKeyPair.builder().privateKey(privateKey).publicKey(publicKey).build();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return null;
        }

        @Bean
        public SecurityFilterConfigure clearSecurityWebFilterConfigure() {
            return new SecurityClearConfigure();
        }


        @Bean
        public SecurityFilterConfigure securityExceptionFilterConfigure() {
            return new SecurityFilterExceptionConfigure(exceptionHandler.getIfAvailable());
        }

        @Bean
        @Primary
        public SecurityFilterConfigure securityFilterConfigure(ObjectProvider<List<SecurityFilterConfigure>> lists) {
            return new DelegatingSecurityFilterConfigure(lists.getIfAvailable());
        }

        @Bean
        @Primary
        public HttpSecurityConfigurerCustomizer httpSecurityConfigurerCustomizer(ObjectProvider<List<HttpSecurityConfigurerCustomizer<AbstractHttpConfigurer>>> lists) {
            return new DelegatingHttpSecurityConfigurerCustomizer<>(lists.getIfAvailable());
        }


        @Bean
        @ConditionalOnMissingBean
        public JsonStrategy defaultJsonStrategy() {
            return new DefaultJsonStrategy();
        }


        @Bean(JsonWebTokenConfig.SUCCESS_HANDLER_BEAN_NAME)
        @ConditionalOnMissingBean
        public AuthenticationSuccessHandler authenticationSuccessHandler(RSAKeyPair rsaKeyPair) {
            return new JsonServerAuthenticationSuccessHandler(defaultJsonStrategy(), rsaKeyPair);
        }

        @Bean(JsonWebTokenConfig.FAIL_HANDLER_BEAN_NAME)
        @ConditionalOnMissingBean
        public AuthenticationFailureHandler authenticationFailureHandler() {
            return new JsonServerAuthenticationFailureHandler(defaultJsonStrategy());
        }

        @Bean(JsonWebTokenConfig.REQUEST_PATH_MATCHER)
        @ConditionalOnMissingBean
        public QueryRequestMatcher queryRequestMatcher(ServerProperties serverProperties, JsonWebTokenProperties properties) {
            QueryRequestMatcher requestMatcher = new QueryRequestMatcher(properties.getQueryTokenParam());
            requestMatcher.setProperties(serverProperties);
            return requestMatcher;
        }

        @Bean
        public MethodSecurityExpressionHandler securityMethodSecurityExpressionHandler() {
            return new SecurityMethodSecurityExpressionHandler();
        }

        @Bean
        public HttpSecurityConfigurerCustomizer jwtSecurityConfigurerCustomizer() {
            return new JsonWebTokenSecurityConfigurerCustomizer();
        }

    }


}
