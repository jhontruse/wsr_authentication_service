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
@Schema(description = "Entidad que representa un rol en el sistema")
@Table("ROL")
public class Rol {

    @Schema(description = "ID único de rol", example = "")
    @Id
    @Column("ID_ROL")
    private String idRol;

    @Schema(description = "Nombre del rol", example = "")
    @Column("NOMBRE_ROL")
    @Size(max = 100, min = 3)
    @NotNull(message = "El campo es obligatorio.")
    private String nombreRol;

    @Schema(description = "Descripcion del rol", example = "")
    @Column("DESCRIPCION_ROL")
    @Size(max = 100, min = 3)
    @NotNull(message = "El campo es obligatorio.")
    private String descripcionRol;

    @Schema(description = "Activo del rol", example = "")
    @Column("ACTIVO_ROL")
    @NotNull(message = "El campo es obligatorio.")
    private Boolean activoRol;

    @Schema(description = "Fecha de creación del rol", example = "")
    @Column("FEC_CREACION_ROL")
    private LocalDateTime fecCreacionRol;

    @Schema(description = "Fecha de actualizacion del rol", example = "")
    @Column("FEC_ACTUALIZA_ROL")
    private LocalDateTime fecActualizaRol;

}
