package com.jhontruse.wsr_authentication_service.security;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import com.jhontruse.wsr_authentication_service.model.entity.Usuario;
import com.jhontruse.wsr_authentication_service.repository.IUsuarioRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthenticationEventListener {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationEventListener.class);

    private final IUsuarioRepository iUsuarioRepository;

    // private static final int MAX_ATTEMPTS = 5;
    @Value("${security.jwt.max-attempts}")
    private String MAX_ATTEMPTS;

    // private static final long TEMP_LOCK_MINUTES = 5; // si usas bloqueo temporal
    @Value("${security.jwt.temp-lock-minutes}")
    private String TEMP_LOCK_MINUTES;

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {

        log.info("********************************");
        log.info("********************************");
        log.info("AuthenticationEventListener - onFailure");
        log.info("********************************");
        log.info("********************************");
        log.info("event: {}", event);

        String username = String.valueOf(event.getAuthentication().getPrincipal());

        log.info("username: {}", username);

        // si tu política incluye bloqueo temporal por expiración del lock, puedes
        // revisar/desbloquear antes
        int x = iUsuarioRepository.executeUnloackUSuarioExpirate(username, Integer.parseInt(TEMP_LOCK_MINUTES),
                LocalDateTime.now(ZoneId.of("America/Lima")));

        log.info("x: {}", x);

        int y = iUsuarioRepository.executeFailedAttempts(username);

        log.info("y: {}", y);

        Optional<Usuario> usuario = iUsuarioRepository.findByUsuario(username);
        log.info("usuario: {}", usuario);
        if (usuario.isPresent() && usuario.get().getIntentoFallidoLoginUsuario() >= Long.parseLong(MAX_ATTEMPTS)) {
            int z = iUsuarioRepository.executeBlockUsuario(LocalDateTime.now(ZoneId.of("America/Lima")), username);
            log.info("z: {}", z);
        }
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        log.info("********************************");
        log.info("********************************");
        log.info("AuthenticationEventListener - onSuccess");
        log.info("********************************");
        log.info("********************************");
        log.info("event: {}", event);
        String username = event.getAuthentication().getName();
        log.info("username: {}", username);
        if (username == null || username.isBlank())
            return;
        int x = iUsuarioRepository.executeResetAttemptAndUnlocked(username);
        log.info("x: {}", x);
    }

}