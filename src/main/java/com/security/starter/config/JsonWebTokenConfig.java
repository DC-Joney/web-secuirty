package com.security.starter.config;

public interface JsonWebTokenConfig {
    String FAIL_HANDLER_BEAN_NAME = "intervalJsonServerAuthenticationFailureHandler";
    String SUCCESS_HANDLER_BEAN_NAME = "intervalJsonServerAuthenticationSuccessHandler";
    String REQUEST_PATH_MATCHER = "intervalJsonbWebTokenRequestMatcher";
    String JSON_WEB_TOKEN_SECURITY_HTTP_CONFIGURER = "intervalJsonWebTokenSecurityHttpConfigurer";
    String JSON_WEB_TOKEN_SECURITY_GLOBAL_CONFIGURER = "intervalJsonWebTokenSecurityGlobalConfigurer";
}
