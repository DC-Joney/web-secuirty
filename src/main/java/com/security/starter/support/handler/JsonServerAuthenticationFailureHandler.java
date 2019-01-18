package com.security.starter.support.handler;

import com.security.starter.support.strategy.JsonStrategy;
import com.security.starter.support.strategy.DefaultJsonStrategy;
import com.security.starter.util.JsonConvertUtils;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Log4j2
public class JsonServerAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private JsonStrategy jsonStrategy;

    public JsonServerAuthenticationFailureHandler(JsonStrategy jsonStrategy){
        this.jsonStrategy = Optional.ofNullable(jsonStrategy).orElseGet(DefaultJsonStrategy::new);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.info(exception);
        jsonStrategy.writeResponse(response,JsonConvertUtils.convertToString(exception));
        SecurityContextHolder.clearContext();
        request.getSession().invalidate();
    }

    public void setJsonStrategy(JsonStrategy jsonStrategy) {
        this.jsonStrategy = jsonStrategy;
    }
}
