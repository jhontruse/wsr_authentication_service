package com.jhontruse.wsr_authentication_service.exception.type;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jhontruse.wsr_authentication_service.exception.ApiErrorFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);

    private final ObjectMapper mapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        try {
            var err = ApiErrorFactory.of(
                    HttpStatus.UNAUTHORIZED.value(),
                    "AUTH_REQUIRED",
                    "No estás autenticado o tu token es inválido.",
                    authException.getClass().getSimpleName(),
                    request,
                    request.getHeader("X-Correlation-Id"),
                    null);
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json");
            mapper.writeValue(response.getWriter(), err);
        } catch (Exception e) {
            log.error("********************************");
            log.error("********************************");
            log.error("JwtAuthenticationEntryPoint - commence");
            log.error("********************************");
            log.error("********************************");
            log.error("e: {}", e);
        }
    }

}
