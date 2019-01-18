package com.security.starter.config;

import com.security.starter.filter.http.GlobalHttpSecurityConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.util.concurrent.atomic.AtomicBoolean;


//全局http链包装
public class GlobalSecurityAdaptor extends WebSecurityConfigurerAdapter {

    @Autowired(required = false)
    private GlobalHttpSecurityConfigurer securityConfigurer;

    private AtomicBoolean INIT_STATE = new AtomicBoolean(false);

    @Override
    protected final void configure(HttpSecurity http) throws Exception {

        if(INIT_STATE.compareAndSet(false,true)){
            securityConfigurer.configure(http);
        }

        //保证 全局http链有一些公用的东西
        securityConfigure(http);

    }

    //包装之后新的方法
    protected  void securityConfigure(HttpSecurity http) throws Exception {
        super.configure(http);
    }

}
