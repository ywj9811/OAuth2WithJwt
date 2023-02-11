package com.example.oauth2WithJwt.controller;

import com.example.oauth2WithJwt.config.auth.PrincipalDetails;
import com.example.oauth2WithJwt.dto.UserDto;
import com.example.oauth2WithJwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/user")
    @ResponseBody
    public String loginFin(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails = {}", principalDetails);
        return "user";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails = {}", principalDetails);
        return "manager";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails = {}", principalDetails);
        return "admin";
    }

    @PostMapping("/join")
    public String join(UserDto userDto) {
        userDto.setPassword(bCryptPasswordEncoder.encode(userDto.getPassword()));
        userService.save(userDto.dtoToDomain());
        return "loginForm.html";
    }

    @GetMapping("/joinForm")
    public String getJoinForm() {
        return "joinForm.html";
    }


    @GetMapping("/loginForm")
    public String getLoginForm() {
        return "loginForm.html";
    }

    @GetMapping("/SnsLogin")
    public String getSnsLoginForm() {
        return "SnsLogin.html";
    }
}
