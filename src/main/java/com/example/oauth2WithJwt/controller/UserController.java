package com.example.oauth2WithJwt.controller;

import com.example.oauth2WithJwt.config.auth.PrincipalDetails;
import com.example.oauth2WithJwt.config.jwt.service.JwtService;
import com.example.oauth2WithJwt.domain.User;
import com.example.oauth2WithJwt.dto.Response;
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
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtService jwtService;

    private Response response = new Response();


    @GetMapping("/user")
    @ResponseBody
    public Response loginFin(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails = {}", principalDetails);
        response.setCode(200);
        response.setMessage("Success");
        response.setResult("user");

        return response;
    }

    @GetMapping("/manager")
    @ResponseBody
    public Response manager(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails = {}", principalDetails);
        response.setCode(200);
        response.setMessage("Success");
        response.setResult("manager");

        return response;
    }

    @GetMapping("/admin")
    @ResponseBody
    public Response admin(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails = {}", principalDetails);
        response.setCode(200);
        response.setMessage("Success");
        response.setResult("admin");

        return response;
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

    @PostMapping("/out")
    @ResponseBody
    public Response logout(HttpServletRequest request, Long userIdx) {
        log.info("accessToken = {}", request.getHeader("Authorization"));
        boolean logout = jwtService.logout(request, userIdx);
        if (logout) {
            response.setMessage("Success");
            response.setCode(200);
            return response;
        }
        response.setMessage("Fail");
        response.setCode(500);
        return response;
    }

    @GetMapping("/user/myPage")
    @ResponseBody
    public Map<String, Object> myPage(HttpServletRequest request) {
        Optional<String> accessToekn = jwtService.extractAccessToken(request);
        if (accessToekn.isEmpty()) {
            return null;
        }
        Optional<String> username = jwtService.extractUsername(accessToekn.get());

        User user = userService.findByUsername(username.get());
        Map<String, Object> response = new HashMap<>();

        UserDto userDto = new UserDto(user.getUsername(), user.getPassword(), user.getEmail());
        response.put("user", userDto);
        response.put("code", 200);
        response.put("message", "success");

        return response;
    }
}
