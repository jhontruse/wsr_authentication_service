package com.jhontruse.wsr_authentication_service.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.jhontruse.wsr_authentication_service.model.dto.ApiError;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final HttpServletRequest request;

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private String cid() {
        return request.getHeader("X-Correlation-Id");
    }

    @ExceptionHandler(DuplicateKeyException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ApiError duplicateKeyApiError(DuplicateKeyException ex) {
        log.error("********************************");
        log.error("********************************");
        log.error("GlobalExceptionHandler - duplicateKeyApiError");
        log.error("********************************");
        log.error("********************************");
        log.error("ex {}", ex);
        return ApiErrorFactory.of(409, "DB_DUPLICATE_KEY",
                "El registro ya existe.",
                ex.getClass().getSimpleName(), request, cid(), null);
    }

    @ExceptionHandler(BadSqlGrammarException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiError badSqlGrammar(BadSqlGrammarException ex) {
        log.error("********************************");
        log.error("********************************");
        log.error("GlobalExceptionHandler - badSqlGrammar");
        log.error("********************************");
        log.error("********************************");
        log.error("ex {}", ex);
        return ApiErrorFactory.of(500, "DB_SQL_ERROR",
                "Error en la sentencia SQL.",
                ex.getClass().getSimpleName(), request, cid(), null);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    public ApiError dataIntegriViolation(DataIntegrityViolationException ex) {
        log.error("********************************");
        log.error("********************************");
        log.error("GlobalExceptionHandler - dataIntegriViolation");
        log.error("********************************");
        log.error("********************************");
        log.error("ex {}", ex);
        return ApiErrorFactory.of(422, "DB_INTEGRITY_VIOLATION",
                "Violación de integridad de datos.",
                ex.getClass().getSimpleName(), request, cid(), null);
    }

    @ExceptionHandler(QueryTimeoutException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ApiError queryTimeOut(QueryTimeoutException ex) {
        log.error("********************************");
        log.error("********************************");
        log.error("GlobalExceptionHandler - queryTimeOut");
        log.error("********************************");
        log.error("********************************");
        log.error("ex {}", ex);
        return ApiErrorFactory.of(503, "DB_TIMEOUT",
                "La base de datos no respondió a tiempo.",
                ex.getClass().getSimpleName(), request, cid(), null);
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiError exception(Exception ex) {
        log.error("********************************");
        log.error("********************************");
        log.error("GlobalExceptionHandler - exception");
        log.error("********************************");
        log.error("********************************");
        log.error("ex {}", ex);
        return ApiErrorFactory.of(500, "DB_ERROR",
                "Error de acceso a datos.",
                ex.getClass().getSimpleName(), request, cid(), null);
    }

}
