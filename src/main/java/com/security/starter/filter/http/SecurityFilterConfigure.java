package com.security.starter.filter.http;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface SecurityFilterConfigure {

     void configure(HttpSecurity http);

}
