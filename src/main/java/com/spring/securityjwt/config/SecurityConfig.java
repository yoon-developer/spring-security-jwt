package com.spring.securityjwt.config;

import com.spring.securityjwt.filter.MyFilter1;
import com.spring.securityjwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final CorsFilter corsFilter;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // Config 정의된 Filter 보다 먼저 실행
    http.csrf().disable();
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // sesstion 사용X
        .and()
        .addFilter(corsFilter) // @CrossOrigin(인증 없을때 사용), 인증이 필요할 경우 Security Filter에 등록
        .formLogin().disable()
        .httpBasic().disable() // header 에 Authorization 필드에 ID, Password 담아서 전달 (토큰  : Bearer)
        .authorizeRequests()
        .antMatchers("/api/v1/user/**")
        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/manager/**")
        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/admin/**")
        .access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll();

  }
}
