package com.security.starter.filter;

import com.security.starter.support.JsonWebAuthenticationToken;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.autoconfigure.security.servlet.StaticResourceRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Log4j2
public class SecurityClearContextFilter extends GenericFilterBean {

    private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

    private SecurityContextRepository sessionRepository = new HttpSessionSecurityContextRepository();

    private SecurityContextRepository repository;

    private RequestMatcher requestMatcher ;

    private  StaticResourceRequest.StaticResourceRequestMatcher staticResourceRequestMatcher = PathRequest.toStaticResources().atCommonLocations();

    public SecurityClearContextFilter(SecurityContextRepository repository
            , RequestMatcher requestMatcher) {
        this.repository = repository;
        this.requestMatcher = requestMatcher;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;

        HttpServletResponse response = (HttpServletResponse) res;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        try {

            if(staticResourceRequestMatcher.matches(request)){
                return;
            }

            if(authentication instanceof JsonWebAuthenticationToken && !(requestMatcher.matches(request))){
                SecurityContextHolder.clearContext();
            }

            filterChain.doFilter(req, res);

        } finally {
            authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication instanceof UsernamePasswordAuthenticationToken) {

                SecurityContextHolder.clearContext();

            } else if (authentication instanceof JsonWebAuthenticationToken) {

                log.info("Save the securityContext in session");

                sessionRepository.saveContext(new SecurityContextImpl(authentication), request, response);
            }
        }


    }





}
