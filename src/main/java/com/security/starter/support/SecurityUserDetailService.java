package com.security.starter.support;

import com.security.starter.service.DemoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class SecurityUserDetailService implements UserDetailsService {

    @Autowired
    private DemoService demoService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return demoService.findByUserName(username);
    }
}
