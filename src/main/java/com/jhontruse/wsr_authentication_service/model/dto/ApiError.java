package com.jhontruse.wsr_authentication_service.model.dto;

import java.time.OffsetDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

@Value
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Entidad que representa un response de excepciones")
public class ApiError {

    @Schema(description = "Tiempo de error", example = "")
    OffsetDateTime timestamp;

    @Schema(description = "Estado de error", example = "")
    int status;

    @Schema(description = "Codigo de error", example = "")
    String code; // Código estable para frontend y logs (ej.: AUTH_LOCKED, JWT_EXPIRED)

    @Schema(description = "Mensaje de error", example = "")
    String message; // Mensaje legible para el usuario

    @Schema(description = "Detalle de error", example = "")
    String detail; // Clase/causa técnica opcional

    @Schema(description = "URL de error", example = "")
    String path; // request.getRequestURI()

    @Schema(description = "Correlativo de error", example = "")
    String correlationId; // si usas MDC o header X-Correlation-Id

    @Schema(description = "Lista de errores de error", example = "")
    List<String> errors; // lista de errores de validación, etc.

}
