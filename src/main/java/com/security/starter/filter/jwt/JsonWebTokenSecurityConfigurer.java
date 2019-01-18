package com.security.starter.filter.jwt;

import com.security.starter.filter.QueryRequestMatcher;
import com.security.starter.support.JsonWebTokenConverter;
import com.security.starter.support.RSAKeyPair;
import com.security.starter.support.TokenConverter;
import com.security.starter.support.handler.NoAuthenticationSuccessHandler;
import com.security.starter.support.jwt.NimbusSecuirtyJwtDecoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class JsonWebTokenSecurityConfigurer extends
        AbstractHttpConfigurer<JsonWebTokenSecurityConfigurer, HttpSecurity> {

    private RSAKeyPair keyPair;

    private AuthenticationSuccessHandler successHandler;

    private AuthenticationFailureHandler failureHandler;

    private TokenConverter tokenConverter;

    private JwtDecoder jwtDecoder;

    private AuthenticationManager authenticationManager;

    private JsonWebTokenAuthenticationFilter authenticationFilter;


    public JsonWebTokenSecurityConfigurer(RSAKeyPair rsaKeyPair){
        this.keyPair = rsaKeyPair;
    }

    public JsonWebTokenSecurityConfigurer successHandler(AuthenticationSuccessHandler successHandler){
        this.successHandler = successHandler;
        return this;
    }

    public JsonWebTokenSecurityConfigurer jsonWebTokenConverter(JsonWebTokenConverter tokenConverter){
        this.tokenConverter = tokenConverter;
        return this;
    }

    public JsonWebTokenSecurityConfigurer failureHandler(AuthenticationFailureHandler failureHandler){
        this.failureHandler = failureHandler;
        return this;
    }

    public JsonWebTokenSecurityConfigurer jwtDecoder(JwtDecoder jwtDecoder){
        this.jwtDecoder = jwtDecoder;
        return this;
    }

    public JsonWebTokenSecurityConfigurer authenticationManager(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        return this;
    }

    public JsonWebTokenSecurityConfigurer authenticationManager(JsonWebTokenAuthenticationFilter authenticationFilter){
        this.authenticationFilter = authenticationFilter;
        return this;
    }



    @Override
    public void configure(HttpSecurity http) throws Exception {

        RequestMatcher requestMatcher = http.getSharedObject(RequestMatcher.class);

        if(tokenConverter == null){
            tokenConverter = new JsonWebTokenConverter();
            ((JsonWebTokenConverter) tokenConverter).setAllowUriQueryParameter(true);
        }

        if(successHandler == null ){
            successHandler = new NoAuthenticationSuccessHandler();
        }

        if (failureHandler == null){
            failureHandler = new NoAuthenticationSuccessHandler();
        }

        if(jwtDecoder == null){
            jwtDecoder = new NimbusSecuirtyJwtDecoder(keyPair.getPublicKey());
        }
        if(authenticationManager == null){
            this.authenticationManager = http.getSharedObject(AuthenticationManager.class);
        }

        if(authenticationFilter == null){
            authenticationFilter = new JsonWebTokenAuthenticationFilter(requestMatcher);
        }

        JsonWebTokenAuthenticationProvider authenticationProvider = new JsonWebTokenAuthenticationProvider(jwtDecoder);

        http.authenticationProvider(authenticationProvider);
        authenticationFilter.setJsonWebTokenResolver(tokenConverter);
        authenticationFilter.setRequiresAuthenticationRequestMatcher(requestMatcher);
        authenticationFilter.setAuthenticationManager(authenticationManager);
        authenticationFilter.setAuthenticationSuccessHandler(successHandler);
        authenticationFilter.setAuthenticationFailureHandler(failureHandler);
        http.addFilterAfter(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }


    public void build(){}

//    private <T> T getSingleBeanOrNull(String beanName, Class<T> type) {
//        try {
//            return getApplicationContext().getBean("",type);
//        } catch (NoSuchBeanDefinitionException e) {}
//        return null;
//    }


}
