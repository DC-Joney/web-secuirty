package com.security.starter.support.strategy;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;


@Log4j2
public class DefaultJsonStrategy implements JsonStrategy {

    private static final String DEFAULT_JSON_STRING = "Warring : The request emerging questions !!!!";

    @Override
    public void writeResponse(HttpServletResponse response, String value) {
        try {
            if (!response.isCommitted()) {
                response.setStatus(HttpStatus.OK.value());
                response.addHeader(MediaType.APPLICATION_JSON_UTF8_VALUE, MediaType.APPLICATION_JSON_UTF8_VALUE);
                String json = Optional.ofNullable(value).orElseGet(this::getDefaultJsonString);
                response.getWriter().write(json);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getDefaultJsonString() {
        log.warn("The request is emerging questions");
        return DEFAULT_JSON_STRING;
    }
}
