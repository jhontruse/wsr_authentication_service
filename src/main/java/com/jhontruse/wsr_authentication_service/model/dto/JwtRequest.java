package com.jhontruse.wsr_authentication_service.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Entidad que representa un Login en el sistema")
public class JwtRequest {

    @Schema(description = "Username único de login", example = "JHONTRUSE")
    private String username;

    @Schema(description = "PASSWORD único de login", example = "123")
    private String password;

}
