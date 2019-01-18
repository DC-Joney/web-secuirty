package com.security.starter.support;

import javax.servlet.http.HttpServletRequest;

public interface TokenConverter {

    String convert(HttpServletRequest request);


}
