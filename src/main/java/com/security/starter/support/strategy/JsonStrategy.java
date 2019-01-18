package com.security.starter.support.strategy;

import javax.servlet.http.HttpServletResponse;

@FunctionalInterface
public interface JsonStrategy {

    void writeResponse(HttpServletResponse response, String attrName);

}
