package com.security.starter.filter;

import com.security.starter.filter.http.SecurityFilterConfigure;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import java.util.Optional;
import java.util.function.Supplier;

public class SecurityFilterExceptionConfigure implements SecurityFilterConfigure {

    private Supplier<ExceptionHandler> exceptionHandlerSupplier = ExceptionTranslationHandler::new;

    private Optional <ExceptionHandler> exceptionHandler = Optional.empty();

    public SecurityFilterExceptionConfigure(ExceptionHandler exceptionHandler){
        this.exceptionHandler = Optional.ofNullable(exceptionHandler);
    }


    private ExceptionHandler getExceptionHandler() {
        return exceptionHandler.orElseGet(exceptionHandlerSupplier);
    }

    @Override
    public void configure(HttpSecurity http) {

        SecurityExceptionFilter exceptionFilter = new SecurityExceptionFilter(getExceptionHandler());

        http.addFilterBefore(exceptionFilter, SecurityContextPersistenceFilter.class);
    }
}
