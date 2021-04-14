package com.spring.securityjwt.config.auth;

import com.spring.securityjwt.domain.User;
import com.spring.securityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login 요청시 동작.
@Service
@RequiredArgsConstructor
public class PrinsipalDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username);
    return new PrinsipalDetails(user);
  }
}
