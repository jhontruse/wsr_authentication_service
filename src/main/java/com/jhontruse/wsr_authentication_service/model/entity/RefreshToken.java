package com.jhontruse.wsr_authentication_service.model.entity;

import java.time.LocalDateTime;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Entidad que representa refresh token en el sistema")
@Table("REFRESH_TOKEN")
public class RefreshToken {

    @Schema(description = "ID único de refresh token", example = "")
    @Id
    @Column("ID_REFRESH_TOKEN")
    private String idRefreshToken;

    @Schema(description = "Token del refresh token", example = "")
    @Column("TOKEN")
    private String token;

    @Schema(description = "Usuario del refresh", example = "")
    @Column("ID_USUARIO")
    private String idUsuario;

    @Schema(description = "Fecha de expiracion de refresh token", example = "")
    @Column("FEC_EXPIRADA")
    private LocalDateTime fecExpirada;

    @Schema(description = "Fecha de creacion de refresh token", example = "")
    @Column("FEC_CREACION_REFRESH_TOKEN")
    private LocalDateTime fecCreacionRefreshToken;

}
