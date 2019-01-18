package com.security.starter.test;

import com.security.starter.config.EnableJwtSecurity;
import com.security.starter.config.JsonWebTokenConfig;
import com.security.starter.filter.SecurityClearContextFilter;
import com.security.starter.support.SecurityUserDetailService;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@EnableJwtSecurity
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(101)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public UserDetailsService userDetailsService(){
        return new SecurityUserDetailService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Autowired
    @Qualifier(JsonWebTokenConfig.SUCCESS_HANDLER_BEAN_NAME)
    private AuthenticationSuccessHandler successHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .formLogin()
                .successHandler(successHandler)
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated();

        http.addFilterAfter(http.getSharedObject(SecurityClearContextFilter.class), SecurityContextPersistenceFilter.class);
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
