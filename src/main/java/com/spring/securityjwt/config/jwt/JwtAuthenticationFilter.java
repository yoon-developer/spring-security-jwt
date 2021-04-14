package com.spring.securityjwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
//import com.spring.securityjwt.config.auth.PrinsipalDetails;
import com.spring.securityjwt.config.auth.PrinsipalDetails;
import com.spring.securityjwt.domain.User;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * UsernamePasswordAuthenticationFilter: login 요청해서 username, password 전송할때 동작
 * 실행순서: attemptAuthentication -> successfulAuthentication
 * */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;

  // login 요청시 동작
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {

    System.out.println("JwtAuthenticationFilter: 로그인 시도중");

    try {
      ObjectMapper om = new ObjectMapper();
      User user = om.readValue(request.getInputStream(), User.class);

      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
          user.getUsername(), user.getPassword());

      // PrincipalDetailsService 의 loadUserByUsername() 함수가 실행됨
      Authentication authentication = authenticationManager.authenticate(authenticationToken);

      // authentication 객체가 session 영역에 저장 (권한관리를 security가 대신 해주기 때문)
      return authentication;

    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }


  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException, ServletException {
    PrinsipalDetails prinsipalDetails = (PrinsipalDetails) authResult.getPrincipal();

    String jwtToken = JWT.create()
        .withSubject(prinsipalDetails.getUsername())
        .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
        .withClaim("id", prinsipalDetails.getUser().getId())
        .withClaim("username", prinsipalDetails.getUser().getUsername())
        .sign(Algorithm.HMAC512(JwtProperties.SECRET));

    response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
  }
}
