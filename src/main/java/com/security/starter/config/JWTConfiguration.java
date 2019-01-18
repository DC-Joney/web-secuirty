package com.security.starter.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.security.starter.filter.ExceptionHandler;
import com.security.starter.filter.http.HttpSecurityConfigurerCustomizer;
import com.security.starter.filter.QueryRequestMatcher;
import com.security.starter.filter.SecurityFilterExceptionConfigure;
import com.security.starter.filter.http.*;
import com.security.starter.filter.http.DelegatingHttpSecurityConfigurerCustomizer;
import com.security.starter.filter.jwt.JsonWebTokenSecurityConfigurer;
import com.security.starter.filter.jwt.JsonWebTokenSecurityConfigurerCustomizer;
import com.security.starter.properties.JsonWebTokenProperties;
import com.security.starter.support.RSAKeyPair;
import com.security.starter.support.SecurityMethodSecurityExpressionHandler;
import com.security.starter.support.handler.JsonServerAuthenticationFailureHandler;
import com.security.starter.support.handler.JsonServerAuthenticationSuccessHandler;
import com.security.starter.support.strategy.DefaultJsonStrategy;
import com.security.starter.support.strategy.JsonStrategy;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

@Log4j2
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@AutoConfigureAfter({AuthenticationConfiguration.class})
@EnableConfigurationProperties(JsonWebTokenProperties.class)
@ConditionalOnMissingBean(RSAKeyPair.class)
@ConditionalOnClass({Jwt.class, JWTClaimsSet.class,AuthenticationConfiguration.class})
public class JWTConfiguration {

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



    @Bean(JsonWebTokenConfig.JSON_WEB_TOKEN_SECURITY_CONFIGURER)
    public JsonWebTokenSecurityConfigurer jsonWebTokenSecurityConfigurer(RSAKeyPair rsaKeyPair){
        return new JsonWebTokenSecurityConfigurer(rsaKeyPair);
    }


    @Bean
    @Primary
    public SecurityFilterConfigure securityFilterConfigure(ObjectProvider<List<SecurityFilterConfigure>> lists) {
        return new DelegatingSecurityFilterConfigure(lists.getIfAvailable());
    }

    @Bean
    @Primary
    public GlobalHttpSecurityConfigurer globalHttpSecurityConfigurer(ObjectProvider<List<GlobalHttpSecurityConfigurer>> lists) {
        return new DelegatingGlobalHttpSecurityConfigure(lists.getIfAvailable());
    }


    @Bean
    @Primary
    public HttpSecurityConfigurerCustomizer httpSecurityConfigurerCustomizer(ObjectProvider<List<HttpSecurityConfigurerCustomizer<AbstractHttpConfigurer>>> lists) {
        return new DelegatingHttpSecurityConfigurerCustomizer<>(lists.getIfAvailable());
    }


    @Bean
    public GlobalHttpSecurityConfigurer clearSecurityWebFilterConfigure(QueryRequestMatcher queryRequestMatcher) {
        return new GlobalHttpSecurityClearConfigurer(queryRequestMatcher);
    }

    @Bean
    public SecurityFilterConfigure securityExceptionFilterConfigure() {
        return new SecurityFilterExceptionConfigure(exceptionHandler.getIfAvailable());
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
