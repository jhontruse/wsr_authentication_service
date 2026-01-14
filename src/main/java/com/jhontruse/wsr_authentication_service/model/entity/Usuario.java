package com.jhontruse.wsr_authentication_service.model.entity;

import java.time.LocalDateTime;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Entidad que representa un usuario en el sistema")
@Table("USUARIO")
public class Usuario {

    @Schema(description = "ID único de usuario", example = "")
    @Id
    @Column("ID_USUARIO")
    private String idUsuario;

    @Schema(description = "Nombre del usuario", example = "")
    @Column("USUARIO")
    @Size(max = 100, min = 3)
    @NotNull(message = "El campo es obligatorio.")
    private String usuario;

    @Schema(description = "Password del usuario", example = "")
    @Column("PASSWORD")
    @Size(max = 800, min = 3)
    @NotNull(message = "El campo es obligatorio.")
    private String password;

    @Schema(description = "Activo del usuario", example = "")
    @Column("ACTIVO_USUARIO")
    @NotNull(message = "El campo es obligatorio.")
    private Boolean activoUsuario; // 1 = activo, 0 = deshabilitado

    @Schema(description = "Fecha de creación del usuario", example = "")
    @Column("FEC_CREACION_USUARIO")
    private LocalDateTime fecCreacionUsuario;

    @Schema(description = "Fecha de actualizacion del usuario", example = "")
    @Column("FEC_ACTUALIZA_USUARIO")
    private LocalDateTime fecActualizaUsuario;

    @Schema(description = "Bloqueo del usuario", example = "")
    @Column("LOCKED_USUARIO")
    private Boolean lockedUsuario; // 1 = bloqueado, 0 = no

    @Schema(description = "Fecha de cuenta expirada del usuario", example = "")
    @Column("FEC_CUENTA_EXPIRADA_USUARIO")
    private LocalDateTime fecCuentaExpiradaUsuario; // fecha de expiración de cuenta

    @Schema(description = "Fecha de password expirada del usuario", example = "")
    @Column("FEC_PASSWORD_EXPIRADA_USUARIO")
    private LocalDateTime fecPasswordExpiradaUsuario; // fecha de expiración de credenciales

    @Schema(description = "Intento fallido de login del usuario", example = "")
    @Column("INTENTO_FALLIDO_LOGIN_USUARIO")
    @NotNull(message = "El campo es obligatorio.")
    private Integer intentoFallidoLoginUsuario; // para políticas de bloqueo

    @Schema(description = "Fecha que se bloqueo usuario", example = "")
    @Column("FEC_BLOQUEO_USUARIO")
    private LocalDateTime fecBloqueoUsuario; // fecha y hora en que se bloqueó la cuenta

}
