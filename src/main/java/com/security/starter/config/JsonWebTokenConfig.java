package com.security.starter.config;

import com.security.starter.support.handler.JsonServerAuthenticationFailureHandler;

public interface JsonWebTokenConfig {
    String FAIL_HANDLER_BEAN_NAME = "intervalJsonServerAuthenticationFailureHandler";
    String SUCCESS_HANDLER_BEAN_NAME = "intervalJsonServerAuthenticationSuccessHandler";
    String REQUEST_PATH_MATCHER = "intervalJsonbWebTokenRequestMatcher";
}
