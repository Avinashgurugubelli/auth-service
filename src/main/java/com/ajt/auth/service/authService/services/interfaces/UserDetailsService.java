package com.ajt.auth.service.authService.services.interfaces;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface  UserDetailsService {
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
