package com.security.starter.test;

import com.security.starter.config.EnableJwtSecurity;
import com.security.starter.config.GlobalSecurityAdaptor;
import com.security.starter.config.JsonWebTokenConfig;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@EnableJwtSecurity(type = EnableJwtSecurity.JsonWebTokenType.GLOBAL)
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(101)
public class SecurityConfig extends GlobalSecurityAdaptor {

    @Bean
    public UserDetailsService userDetailsService(){
        return new SecurityUserDetailService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Autowired(required = false)
    @Qualifier(JsonWebTokenConfig.SUCCESS_HANDLER_BEAN_NAME)
    private AuthenticationSuccessHandler successHandler;

    @Override
    protected void securityConfigure(HttpSecurity http) throws Exception {

        FormLoginConfigurer<HttpSecurity> loginConfigurer = http.formLogin();

        if(successHandler != null){
            loginConfigurer.successHandler(successHandler);
        }

        http.csrf().disable()
                .authorizeRequests()
                .anyRequest()
                .authenticated();

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        UserDetailsService userDetailsService = getSingleBeanOrNull(UserDetailsService.class);
        PasswordEncoder passwordEncoder = getSingleBeanOrNull(PasswordEncoder.class);
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);

    }

    private <T> T getSingleBeanOrNull(Class<T> type) {
        try {
            return getApplicationContext().getBean(type);
        } catch (NoSuchBeanDefinitionException e) {
        }
        return null;
    }


}
