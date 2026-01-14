package com.jhontruse.wsr_authentication_service.repository;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.jhontruse.wsr_authentication_service.model.entity.Usuario;

@Repository
public interface IUsuarioRepository extends CrudRepository<Usuario, String>,
                PagingAndSortingRepository<Usuario, String> {

        Optional<Usuario> findByUsuario(String usuario);

        /**
         * (Opcional) Desbloqueo por expiración del bloqueo temporal.
         * Si el bloqueo ya excedió el umbral, desbloquea y limpia intentos.
         */
        @Modifying
        @Query(value = "UPDATE USUARIO SET LOCKED_USUARIO = 0, FEC_BLOQUEO_USUARIO = NULL, INTENTO_FALLIDO_LOGIN_USUARIO = 0, FEC_ACTUALIZA_USUARIO = CURRENT_TIMESTAMP WHERE USUARIO = :usuario AND LOCKED_USUARIO = 1 AND FEC_BLOQUEO_USUARIO IS NOT NULL AND TIMESTAMPADD (MINUTE, :minutesThreshold, FEC_BLOQUEO_USUARIO) <= :now", name = "executeUnloackUSuarioExpirate")
        int executeUnloackUSuarioExpirate(
                        @Param("usuario") String usuario,
                        @Param("minutesThreshold") long minutesThreshold,
                        @Param("now") LocalDateTime now);

        /**
         * Incrementa los intentos fallidos.
         * Úsalo en AuthenticationSuccessEvent.
         */
        @Transactional
        @Modifying
        @Query(value = "UPDATE USUARIO SET INTENTO_FALLIDO_LOGIN_USUARIO = INTENTO_FALLIDO_LOGIN_USUARIO + 1, FEC_ACTUALIZA_USUARIO = CURRENT_TIMESTAMP WHERE USUARIO = :usuario", name = "executeFailedAttempts")
        int executeFailedAttempts(@Param("usuario") String usuario);

        /**
         * Bloqueo de usuario por intentos fallidos.
         * Úsalo en AuthenticationSuccessEvent.
         */
        @Transactional
        @Modifying
        @Query(value = "UPDATE USUARIO SET LOCKED_USUARIO = 1, FEC_BLOQUEO_USUARIO = :lockedAt, FEC_ACTUALIZA_USUARIO = CURRENT_TIMESTAMP WHERE USUARIO = :usuario", name = "executeBlockUsuario")
        int executeBlockUsuario(
                        @Param("lockedAt") LocalDateTime lockedAt,
                        @Param("usuario") String usuario);

        /**
         * Resetea intentos fallidos y desbloquea si estaba bloqueado.
         * Úsalo en AuthenticationSuccessEvent.
         */
        @Transactional
        @Modifying
        @Query(value = "UPDATE USUARIO SET INTENTO_FALLIDO_LOGIN_USUARIO = 0, LOCKED_USUARIO = 0, FEC_BLOQUEO_USUARIO = NULL, FEC_ACTUALIZA_USUARIO = CURRENT_TIMESTAMP WHERE  USUARIO = :usuario", name = "executeResetAttemptAndUnlocked")
        int executeResetAttemptAndUnlocked(String usuario);

}