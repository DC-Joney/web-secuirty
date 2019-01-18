package com.security.starter.support.handler;

import com.security.starter.support.strategy.JsonStrategy;
import com.security.starter.support.RSAKeyPair;
import com.security.starter.support.strategy.DefaultJsonStrategy;
import com.security.starter.util.JsonConvertUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

public class JsonServerAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private JsonStrategy jsonStrategy;
    private RSAKeyPair rsaKeyPair;

    public JsonServerAuthenticationSuccessHandler(JsonStrategy jsonStrategies, RSAKeyPair rsaKeyPair){
        this.jsonStrategy = Optional.ofNullable(jsonStrategies).orElseGet(DefaultJsonStrategy::new);
        this.rsaKeyPair = rsaKeyPair;
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        jsonStrategy.writeResponse(response,JsonConvertUtils.convertToJWtString(authentication, rsaKeyPair));

    }


    public void setJsonStrategy(JsonStrategy jsonStrategy) {
        this.jsonStrategy = jsonStrategy;
    }
}
