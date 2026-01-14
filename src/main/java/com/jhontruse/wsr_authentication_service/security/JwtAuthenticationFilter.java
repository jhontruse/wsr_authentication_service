package com.jhontruse.wsr_authentication_service.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        log.info("********************************");
        log.info("********************************");
        log.info("JwtAuthenticationFilter - doFilterInternal");
        log.info("********************************");
        log.info("********************************");

        final String authHeader = request.getHeader("Authorization");

        log.info("authHeader: {}", authHeader);

        String username = null;
        String jwt = null;

        log.info("username: {}", username);
        log.info("jwt: {}", jwt);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);

        log.info("jwt: {}", jwt);

        try {
            username = jwtService.getUsernameFromToken(jwt);

            log.info("username: {}", username);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                log.info("userDetails: {}", userDetails);

                log.info("jwtService.validateToken: {}", jwtService.validateToken(jwt, userDetails));

                if (jwtService.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities());
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.info("authToken: {}", authToken);
                }
            }

        } catch (Exception e) {
            log.info("********************************");
            log.info("********************************");
            log.info("JwtAuthenticationFilter - doFilterInternal");
            log.info("********************************");
            log.info("********************************");
            log.info("e: {}", e);
            request.setAttribute("msg", e.getMessage());
        }
        log.info("request: {}", request);
        log.info("response: {}", response);
        filterChain.doFilter(request, response);

    }

}
