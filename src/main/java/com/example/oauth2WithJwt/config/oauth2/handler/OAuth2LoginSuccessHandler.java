package com.example.oauth2WithJwt.config.oauth2.handler;

import com.example.oauth2WithJwt.config.auth.PrincipalDetails;
import com.example.oauth2WithJwt.config.auth.PrincipalDetailsService;
import com.example.oauth2WithJwt.config.jwt.service.JwtService;
import com.example.oauth2WithJwt.domain.User;
import com.example.oauth2WithJwt.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * OAuth2 로그인 성공시 로직 작성
 */
@RequiredArgsConstructor
@Component
@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtService jwtService;
    private final UserRepo userRepo;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 로그인 성공");
        try {
//            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
//            // User의 Role이 GUEST일 경우 처음 요청한 회원이므로 회원가입 페이지로 리다이렉트
//            if(principalDetails.getUser().getRole().equals("ROLE_GUEST") ) {
//                String accessToken = jwtService.createAccessToken(principalDetails.getUsername());
//                response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken);
//                response.sendRedirect("oauth2/sign-up"); // 프론트의 회원가입 추가 정보 입력 폼으로 리다이렉트
//
//                jwtService.sendAccessAndRefreshToken(response, accessToken, null);
////                User findUser = userRepository.findByEmail(oAuth2User.getEmail())
////                                .orElseThrow(() -> new IllegalArgumentException("이메일에 해당하는 유저가 없습니다."));
////                findUser.authorizeUser();
//            } else {
//                loginSuccess(response, oAuth2User); // 로그인에 성공한 경우 access, refresh 토큰 생성
//            }
            //현재는 Sns로그인 이후 회원가입 로직이 계획되지 않아서 주석 처리
            loginSuccess(response, (PrincipalDetails) authentication.getPrincipal());
        } catch (Exception e) {
            throw e;
        }
    }

    private void loginSuccess(HttpServletResponse response, PrincipalDetails principalDetails) throws IOException {
        String accessToken = jwtService.createAccessToken(principalDetails.getUsername());
        String refreshToken = jwtService.createRefreshToken();

//        response.addHeader(jwtService.getAccessHeader(), "Bearer " + accessToken);
//        response.addHeader(jwtService.getRefreshHeader(), "Bearer " + refreshToken);

        jwtService.updateRefreshToken(principalDetails.getUsername(), refreshToken);
        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);
    }
    /**
     * 현재 : 무조건 토큰 생성함
     * but
     * JWT 인증 필터처럼 RefreshToken 유/무에 따라 다르게 처리하자
     */
}
