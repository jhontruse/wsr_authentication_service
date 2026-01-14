package com.jhontruse.wsr_authentication_service.exception;

import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jhontruse.wsr_authentication_service.model.dto.ApiError;

import jakarta.servlet.http.HttpServletRequest;

public class ApiErrorFactory {

    private static final ZoneId LIMA = ZoneId.of("America/Lima");

    private static final Logger log = LoggerFactory.getLogger(ApiErrorFactory.class);

    private ApiErrorFactory() {
    }

    public static ApiError of(int status, String code, String message,
            String detail, HttpServletRequest req, String correlationId,
            List<String> errors) {
        log.error("********************************");
        log.error("********************************");
        log.error("ApiErrorFactory - ApiError");
        log.error("********************************");
        log.error("********************************");
        log.error("status {}", status);
        log.error("code {}", code);
        log.error("message {}", message);
        log.error("detail {}", detail);
        log.error("req {}", req);
        log.error("correlationId {}", correlationId);
        log.error("errors {}", errors);

        return ApiError.builder()
                .timestamp(OffsetDateTime.now(LIMA))
                .status(status)
                .code(code)
                .message(message)
                .detail(detail)
                .path(req != null ? req.getRequestURI() : null)
                .correlationId(correlationId)
                .errors(errors)
                .build();
    }

}
