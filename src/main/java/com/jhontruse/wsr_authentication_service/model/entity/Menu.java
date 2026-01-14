package com.jhontruse.wsr_authentication_service.model.entity;

import java.time.LocalDateTime;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Entidad que representa un menú en el sistema")
@Table("MENU")
public class Menu {

    @Schema(description = "ID único de menu", example = "")
    @Id
    @Column("ID_MENU")
    private String idMenu;

    @Schema(description = "Nombre del menú", example = "")
    @Column("NOMBRE_MENU")
    @Size(max = 100, min = 3)
    @NotNull(message = "El campo es obligatorio.")
    private String nombreMenu;

    @Schema(description = "Ruta del menú", example = "")
    @Column("RUTA_MENU")
    @Size(max = 100, min = 3)
    @NotNull(message = "El campo es obligatorio.")
    private String rutaMenu;

    @Schema(description = "Icono del menú", example = "")
    @Column("ICONO_MENU")
    @Size(max = 100, min = 3)
    @NotNull(message = "El campo es obligatorio.")
    private String iconoMenu;

    @Schema(description = "Orden del menú", example = "")
    @Column("ORDEN_MENU")
    @NotNull(message = "El campo es obligatorio.")
    @Positive(message = "El campo debe ser positivo.")
    private Integer ordenMenu;

    @Schema(description = "Padre del menú", example = "")
    @Column("PADRE_ID_MENU")
    private String padreIdMenu;

    @Schema(description = "Visible del menú", example = "")
    @Column("VISIBLE_MENU")
    @NotNull(message = "El campo es obligatorio.")
    private Boolean visibleMenu;

    @Schema(description = "Activo del menú", example = "")
    @Column("ACTIVO_MENU")
    @NotNull(message = "El campo es obligatorio.")
    private Boolean activoMenu;

    @Schema(description = "Fecha de creación del menú", example = "")
    @Column("FEC_CREACION_MENU")
    private LocalDateTime fecCreacionMenu;

    @Schema(description = "Fecha de actualizacion del menú", example = "")
    @Column("FEC_ACTUALIZA_MENU")
    private LocalDateTime fecActualizaMenu;

}
