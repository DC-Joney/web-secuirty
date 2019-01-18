package com.security.starter.support.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.starter.support.exception.JsonWebTokenError;
import org.springframework.core.convert.converter.Converter;

public class TokenErrorConverter implements Converter<JsonWebTokenError,String> {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convert(JsonWebTokenError source) {
        try {
            return objectMapper.writeValueAsString(source);
        } catch (JsonProcessingException e) {
            return e.getMessage();
        }
    }
}
