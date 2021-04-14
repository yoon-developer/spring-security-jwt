package com.spring.securityjwt.config.jwt;

public interface JwtProperties {
  String SECRET = "secret"; // 우리 서버만 알고 있는 비밀값
  int EXPIRATION_TIME = 60000 * 60; // 60분
  String TOKEN_PREFIX = "Bearer ";
  String HEADER_STRING = "Authorization";
}
