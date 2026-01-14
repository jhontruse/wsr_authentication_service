package com.jhontruse.wsr_authentication_service.repository;

import java.util.List;

import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.jhontruse.wsr_authentication_service.model.entity.Menu;

@Repository
public interface IMenuRepository extends CrudRepository<Menu, String>,
                PagingAndSortingRepository<Menu, String> {

        @Query("SELECT M.* FROM MENU M INNER JOIN ROL_MENU RM ON M.ID_MENU = RM.ID_MENU INNER JOIN ROL R ON R.ID_ROL = RM.ID_ROL INNER JOIN USUARIO_ROL UR ON UR.ID_ROL = R.ID_ROL INNER JOIN USUARIO U ON U.ID_USUARIO = UR.ID_USUARIO WHERE U.USUARIO = :usuario ORDER BY M.ORDEN_MENU")
        List<Menu> executeUsuarioMenuSearch(
                        @Param("usuario") String usuario);

}
