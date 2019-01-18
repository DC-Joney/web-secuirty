package com.security.starter.filter;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class SecurityExceptionFilter extends OncePerRequestFilter {

     private ExceptionHandler exceptionHandler;

     public SecurityExceptionFilter(ExceptionHandler exceptionHandler){
          this.exceptionHandler = exceptionHandler;
     }

     @Override
     protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
          try {
               chain.doFilter(request,response);
          }catch (Throwable e){
               if(logger.isInfoEnabled()){
                    logger.info(e);
               }
               exceptionHandler.doException(request,response,e);

          }
          finally {
               if(!response.isCommitted()){
                   response.setStatus(HttpStatus.OK.value());
               }
          }
     }
}
