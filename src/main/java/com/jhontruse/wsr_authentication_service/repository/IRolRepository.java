package com.jhontruse.wsr_authentication_service.repository;

import java.util.List;

import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.jhontruse.wsr_authentication_service.model.entity.Rol;

@Repository
public interface IRolRepository extends CrudRepository<Rol, String>,
                PagingAndSortingRepository<Rol, String> {

        @Query("SELECT R.* FROM ROL R INNER JOIN USUARIO_ROL UR ON UR.ID_ROL = R.ID_ROL INNER JOIN USUARIO U ON U.ID_USUARIO = UR.ID_USUARIO WHERE U.USUARIO = :usuario ")
        List<Rol> executeUsuarioRolSearch(
                        @Param("usuario") String usuario);

}
