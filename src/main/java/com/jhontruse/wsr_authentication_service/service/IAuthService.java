package com.jhontruse.wsr_authentication_service.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface IAuthService {

    public String login(String username, String password, UserDetails userDetails);

    public String refreshLogin(String username, String password, UserDetails userDetails);

}
