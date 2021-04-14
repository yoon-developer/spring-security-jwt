package com.spring.securityjwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.spring.securityjwt.config.auth.PrinsipalDetails;
import com.spring.securityjwt.domain.User;
import com.spring.securityjwt.repository.UserRepository;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

  private UserRepository userRepository;

  public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
      UserRepository userRepository) {
    super(authenticationManager);
    this.userRepository = userRepository;
  }

  // 인증이나 권한이 필요한 주소요청이 있을때 사용
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {
    System.out.println("인증이나 권한이 필요한 주소 요청이 됨");

    String header = request.getHeader("Authorization");
    System.out.println(header);

    // header 확인
    if (header == null || !header.startsWith("Bearer")) {
      chain.doFilter(request, response);
      return;
    }

    String token = header.replace("Bearer ", "");

    String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token)
        .getClaim("username").asString();

    if (username != null) {
      User user = userRepository.findByUsername(username);

      PrinsipalDetails prinsipalDetails = new PrinsipalDetails(user);

      Authentication authentication = new UsernamePasswordAuthenticationToken(prinsipalDetails,
          null, prinsipalDetails.getAuthorities());

      // 강제로 시큐리티의 세션의 접근하여 authentication 객체를 저장
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    chain.doFilter(request, response);
  }
}
