package com.security.starter.filter.jwt;

import com.security.starter.filter.QueryTokenAuthentication;
import com.security.starter.support.JsonWebAuthenticationToken;
import com.security.starter.support.JsonWebTokenSecurityContext;
import com.security.starter.support.TokenConverter;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Optional;

@Log4j2
public class JsonWebTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private TokenConverter tokenConverter;

    private SecurityContextRepository sessionRepository = new HttpSessionSecurityContextRepository();

    protected JsonWebTokenAuthenticationFilter(RequestMatcher requestMatcher) {
        super(requestMatcher);
        setContinueChainBeforeSuccessfulAuthentication(true);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        Authentication authentication = null;

        QueryTokenAuthentication jsonWebToken = new QueryTokenAuthentication(tokenConverter.convert(request));

        if (checkSecurityContext(jsonWebToken, request,response)) {

            HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);

            authentication = sessionRepository.loadContext(holder).getAuthentication();

            if (authentication == null || !(authentication instanceof JsonWebAuthenticationToken)) {
                authentication = generateAuthenticationToken(jsonWebToken);
            }
        } else {
            authentication = generateAuthenticationToken(jsonWebToken);
        }

        if (authentication != null) {
            successfulAuthentication(request, response, authentication);
        }

        return authentication;
    }

    private boolean checkSecurityContext(QueryTokenAuthentication jsonWebToken, HttpServletRequest request, HttpServletResponse response) {

        return Optional.ofNullable(jsonWebToken.getToken())
                .filter(bool -> sessionRepository.containsContext(request))
                .map(tokenCode -> getTokenCode(new HttpRequestResponseHolder(request, response)))
                .map(tokenCode -> tokenCode.equals(jsonWebToken.getToken()))
                .orElse(false);

    }


    private String getTokenCode(HttpRequestResponseHolder responseHolder){
        SecurityContext securityContext = sessionRepository.loadContext(responseHolder);
        Authentication authentication = securityContext.getAuthentication();
        if (authentication instanceof JsonWebAuthenticationToken) {
            JsonWebAuthenticationToken authenticationToken  = (JsonWebAuthenticationToken) authentication;
            return authenticationToken.getToken().getTokenValue();
        }
        return null;
    }




    private Authentication generateAuthenticationToken(QueryTokenAuthentication jsonWebToken) {


        Authentication authentication = getAuthenticationManager().authenticate(jsonWebToken);

        log.info("The session cache is null,generate the jsonWebAuthenticationToken");

        return authentication;
    }


    private void successfulAuthentication(HttpServletRequest request,
                                          HttpServletResponse response, Authentication authResult) {


        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success. Updating SecurityContextHolder to contain: "
                    + authResult);
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);


        getRememberMeServices().loginSuccess(request, response, authResult);

        // Fire event
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
                    authResult, this.getClass()));
        }
    }


    public void setJsonWebTokenResolver(TokenConverter tokenConverter) {
        this.tokenConverter = tokenConverter;
    }
}
