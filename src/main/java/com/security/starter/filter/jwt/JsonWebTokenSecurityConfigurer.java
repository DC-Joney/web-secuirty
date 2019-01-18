package com.security.starter.filter.jwt;

import com.security.starter.config.HttpSecurityConfigurer;
import com.security.starter.filter.QueryRequestMatcher;
import com.security.starter.support.JsonWebTokenConverter;
import com.security.starter.support.RSAKeyPair;
import com.security.starter.support.TokenConverter;
import com.security.starter.support.handler.NoAuthenticationSuccessHandler;
import com.security.starter.support.jwt.NimbusSecuirtyJwtDecoder;
import com.sun.org.apache.regexp.internal.RE;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@HttpSecurityConfigurer
public class JsonWebTokenSecurityConfigurer<H extends HttpSecurity> extends
        AbstractHttpConfigurer<JsonWebTokenSecurityConfigurer<H>, HttpSecurity> {

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

    public JsonWebTokenSecurityConfigurer<H> successHandler(AuthenticationSuccessHandler successHandler){
        this.successHandler = successHandler;
        return this;
    }

    public JsonWebTokenSecurityConfigurer<H> jsonWebTokenConverter(JsonWebTokenConverter tokenConverter){
        this.tokenConverter = tokenConverter;
        return this;
    }

    public JsonWebTokenSecurityConfigurer<H> failureHandler(AuthenticationFailureHandler failureHandler){
        this.failureHandler = failureHandler;
        return this;
    }

    public JsonWebTokenSecurityConfigurer<H> jwtDecoder(JwtDecoder jwtDecoder){
        this.jwtDecoder = jwtDecoder;
        return this;
    }

    public JsonWebTokenSecurityConfigurer<H> authenticationManager(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        return this;
    }

    public JsonWebTokenSecurityConfigurer<H> authenticationManager(JsonWebTokenAuthenticationFilter authenticationFilter){
        this.authenticationFilter = authenticationFilter;
        return this;
    }



    @Override
    public void configure(HttpSecurity http) throws Exception {

        QueryRequestMatcher requestMatcher = http.getSharedObject(QueryRequestMatcher.class);

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
