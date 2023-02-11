package com.example.oauth2WithJwt.config.login.handler;

import com.example.oauth2WithJwt.config.auth.PrincipalDetails;
import com.example.oauth2WithJwt.config.jwt.service.JwtService;
import com.example.oauth2WithJwt.domain.User;
import com.example.oauth2WithJwt.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtService jwtService;
    private final UserRepo userRepo;

    @Value("${jwt.access.expiration}")
    private String accessTokenExpiration;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String username = extractUsername(authentication); //인증 정보에서 username 가져옴
        String accessToken = jwtService.createAccessToken(username); //JwtService에서 AccessToken 발급
        String refreshToken = jwtService.createRefreshToken(); //JwtService에서 RefreshToken 발급

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
        //응답 헤더에 accessToken, refreshToken 장착

        Optional<User> byUsername = userRepo.findByUsername(username);
        if (byUsername.isPresent()) {
            User user = byUsername.get();
            user.updateRefreshToken(refreshToken);
            userRepo.saveAndFlush(user);
        }
        log.info("로그인 성공 username : {}", username);
        log.info("로그인 성공 AccessToken : {}", accessToken);
        log.info("토큰 만료 기간 : {}", accessTokenExpiration);
    }

    private String extractUsername(Authentication authentication) {
        PrincipalDetails userDetails = (PrincipalDetails) authentication.getPrincipal();
        return userDetails.getUsername();
    }
}
