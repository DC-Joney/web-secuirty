package com.security.starter.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface ExceptionHandler{

    void doException(HttpServletRequest request, HttpServletResponse response, Throwable throwable) throws IOException;
}
