package com.security.starter.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DemoService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UserDetails findByUserName(String userName){
        return User.withUsername(userName)
                .password("admin")
                .passwordEncoder(pass-> passwordEncoder.encode(pass))
                .roles("ADMIN")
                .build();
    }

}
