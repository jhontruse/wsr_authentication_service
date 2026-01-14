package com.jhontruse.wsr_authentication_service.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.jhontruse.wsr_authentication_service.model.dto.JwtRequest;
import com.jhontruse.wsr_authentication_service.model.record.JwtResponse;
import com.jhontruse.wsr_authentication_service.security.CustomUserDetailsService;
import com.jhontruse.wsr_authentication_service.service.impl.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@Tag(name = "Auth", description = "Gestión de login del sistema cita medica")
@SecurityRequirement(name = "bearerAuth")
public class LoginController {

    @Autowired
    private final AuthenticationManager authenticationManager;

    @Autowired
    private final CustomUserDetailsService customUserDetailsService;

    @Autowired
    private final AuthService authService;

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    private void authenticate(String username, String password) throws Exception {
        log.info("********************************");
        log.info("********************************");
        log.info("LoginController - authenticate");
        log.info("********************************");
        log.info("********************************");
        log.info("username: {}", username);
        log.info("password: {}", password);
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }

    @Operation(summary = "Autenticación", description = "Autenticación de usuarios en el sistema cita medica")
    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(
            @Parameter(description = "Credenciales", example = "JHONTRUSE / 123", required = true) @RequestBody JwtRequest req)
            throws Exception {
        log.info("********************************");
        log.info("********************************");
        log.info("LoginController - login");
        log.info("********************************");
        log.info("********************************");
        log.info("req: {}", req);
        authenticate(req.getUsername(), req.getPassword());
        final UserDetails userDetails = customUserDetailsService.loadUserByUsername(req.getUsername());
        log.info("userDetails: {}", userDetails);
        final String token = authService.login(req.getUsername(), req.getPassword(), userDetails);
        final String tokenRefresh = authService.refreshLogin(req.getUsername(), req.getPassword(), userDetails);
        log.info("token: {}", token);
        return ResponseEntity.ok(new JwtResponse(token, "Bearer", tokenRefresh));
    }

}
