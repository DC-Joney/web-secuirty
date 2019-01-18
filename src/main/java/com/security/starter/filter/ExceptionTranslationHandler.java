package com.security.starter.filter;

import com.security.starter.support.exception.JsonWebTokenError;
import com.security.starter.support.exception.JwtAuthenticationException;
import com.security.starter.support.exception.WrappedError;
import com.security.starter.support.strategy.DefaultJsonStrategy;
import com.security.starter.support.strategy.JsonStrategy;
import com.security.starter.util.JsonConvertUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ExceptionTranslationHandler  implements ExceptionHandler{

    private JsonStrategy jsonStrategy = new DefaultJsonStrategy();

    private static Map<Class<? extends Throwable>,HttpStatus> errorMap = new ConcurrentHashMap<>();

    private static final String DEFAYLT_MESSAGE = "No message available";

    static {
        errorMap.putIfAbsent(AccessDeniedException.class,HttpStatus.FORBIDDEN);
        errorMap.put(JwtAuthenticationException.class,HttpStatus.UNAUTHORIZED);
        errorMap.put(AuthenticationException.class,HttpStatus.UNAUTHORIZED);
    }


    @Override
    public void doException(HttpServletRequest request, HttpServletResponse response, Throwable throwable) throws IOException {

        JsonWebTokenError tokenError ;

        HttpStatus httpStatus = errorMap.get(throwable.getClass());

        if(httpStatus == null){
            httpStatus = HttpStatus.FORBIDDEN;
        }

        if(throwable instanceof JwtAuthenticationException){
            JwtAuthenticationException authenticationException = (JwtAuthenticationException) throwable;
            tokenError = authenticationException.getError();

        }else {
            tokenError = new JsonWebTokenError(httpStatus.getReasonPhrase(),httpStatus,throwable.getMessage());
        }

       response.sendError(tokenError.getHttpStatus().value(),tokenError.getDescription());

    }
}
