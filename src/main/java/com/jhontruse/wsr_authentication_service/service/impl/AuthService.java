package com.jhontruse.wsr_authentication_service.service.impl;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.jhontruse.wsr_authentication_service.model.entity.Menu;
import com.jhontruse.wsr_authentication_service.repository.IMenuRepository;
import com.jhontruse.wsr_authentication_service.security.JwtService;
import com.jhontruse.wsr_authentication_service.service.IAuthService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService implements IAuthService {

    @Autowired
    private final IMenuRepository iMenuRepository;

    @Autowired
    private final JwtService jwtService;

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    @Override
    public String login(String username, String password, UserDetails userDetails) {
        log.info("********************************");
        log.info("********************************");
        log.info("AuthService - login");
        log.info("********************************");
        log.info("********************************");
        log.info("username: {}", username);
        log.info("password: {}", password);
        log.info("userDetails: {}", userDetails);
        List<String> menus = iMenuRepository.executeUsuarioMenuSearch(username).stream()
                .map(Menu::getNombreMenu)
                .toList();
        log.info("menus: {}", menus);
        return jwtService.generateToken(userDetails, menus);
    }

    @Override
    public String refreshLogin(String username, String password, UserDetails userDetails) {
        log.info("********************************");
        log.info("********************************");
        log.info("AuthService - refreshLogin");
        log.info("********************************");
        log.info("********************************");
        log.info("username: {}", username);
        log.info("password: {}", password);
        log.info("userDetails: {}", userDetails);
        List<String> menus = iMenuRepository.executeUsuarioMenuSearch(username).stream()
                .map(Menu::getNombreMenu)
                .toList();
        log.info("menus: {}", menus);
        return jwtService.generateRefreshToken(userDetails, menus);
    }

}
