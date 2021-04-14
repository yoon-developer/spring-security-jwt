package com.spring.securityjwt.api;

import com.spring.securityjwt.config.auth.PrinsipalDetails;
import com.spring.securityjwt.domain.User;
import com.spring.securityjwt.repository.UserRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1")
public class RestApiController {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  @GetMapping("/home")
  public String home() {
    return "<h1>home<h1>";
  }

  @PostMapping("/token")
  public String token() {
    return "<h1>token<h1>";
  }

  @PostMapping("/join")
  public String join(@RequestBody User user) {
    user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    user.setRoles("ROLE_USER");
    userRepository.save(user);
    return "회원가입완료";
  }

  @GetMapping("/user")
  public String user(Authentication authentication) {
    PrinsipalDetails prinsipalDetails = (PrinsipalDetails) authentication.getPrincipal();
    System.out.println("principal= " + prinsipalDetails.getUser().getId());
    System.out.println("principal= " + prinsipalDetails.getUser().getUsername());
    System.out.println("principal= " + prinsipalDetails.getUser().getPassword());
    return "User";
  }

  @GetMapping("/manager")
  public String manager() {
    return "Manager";
  }

  @GetMapping("/admin")
  public String admin(){
    return "Admin";
  }

}
