package com.security.starter.web;

import com.security.starter.filter.method.PermissionAuthorize;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Log4j2
@RestController
public class DemoController {

    @PreAuthorize("hasRoles('ADMIN')")
    @GetMapping("/test")
    public Authentication test(@AuthenticationPrincipal Authentication authentication){
        return authentication;
    }

    @PreAuthorize("hasRole('ADMIN_T')")
    @GetMapping("/test1")
    public Authentication test1(@AuthenticationPrincipal Authentication authentication){
        return authentication;
    }

    @PermissionAuthorize("hasRoles('ADMIN')")
    @GetMapping("/test2")
    public Authentication test2(@AuthenticationPrincipal Authentication authentication){
        return authentication;
    }

}
