package com.gwkim.security.oauth2.core.authentication.userdetails.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService {

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }
}
