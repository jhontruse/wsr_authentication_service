package com.jhontruse.wsr_authentication_service.exception.type;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jhontruse.wsr_authentication_service.exception.ApiErrorFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private static final Logger log = LoggerFactory.getLogger(RestAccessDeniedHandler.class);

    private final ObjectMapper mapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException, ServletException {
        try {
            var err = ApiErrorFactory.of(
                    HttpStatus.FORBIDDEN.value(),
                    "AUTH_FORBIDDEN",
                    "No tienes permisos para acceder a este recurso.",
                    accessDeniedException.getClass().getSimpleName(),
                    request,
                    request.getHeader("X-Correlation-Id"),
                    null);
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType("application/json");
            mapper.writeValue(response.getWriter(), err);
        } catch (Exception e) {
            log.error("********************************");
            log.error("********************************");
            log.error("RestAccessDeniedHandler - handle");
            log.error("********************************");
            log.error("********************************");
            log.error("e: {}", e);
        }
    }

}
