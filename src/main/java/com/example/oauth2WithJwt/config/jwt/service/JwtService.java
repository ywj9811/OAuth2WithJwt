package com.example.oauth2WithJwt.config.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.example.oauth2WithJwt.domain.User;
import com.example.oauth2WithJwt.repository.RedisRepo;
import com.example.oauth2WithJwt.repository.UserRepo;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Getter
@Slf4j
public class JwtService {
    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    /**
     * JWT의 Subject와 Claim으로 username 사용 -> 클레임의 name을 "username"으로 설정
     * JWT의 헤더에 들어오는 값 : 'Authorization(Key) = Bearer {토큰} (Value)' 형식
     * 토큰은 자동으로 Bearer + 값 이렇게 생긴다.
     */
    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String USERNAME_CLAIM = "username";
    private static final String USERIDX_CLAIM = "userIdx";
    private static final String BEARER = "Bearer ";

    private final UserRepo userRepository;

    private final RedisRepo redisRepo;

    /**
     * Redis 사용 로그아웃 : AccessToken 블랙 리스트 및 RefershToken 삭제
     */
    public boolean logout(HttpServletRequest request, Long userIdx) {
        Optional<String> optionalAccessToken = extractAccessToken(request);
        if (optionalAccessToken.isEmpty())
            throw new JwtException("AccessToken이 올바르지 않습니다.");
        String accessToken = optionalAccessToken.get();
        try {
            JWT.require(Algorithm.HMAC512(secretKey)).build().verify(accessToken);
            Long expiration = getExpiration(accessToken);
            log.info("AccessToken 블랙리스트 등록 {}", accessToken);
            redisRepo.setValues(accessToken, "logout", Duration.ofMillis(expiration));
        } catch (TokenExpiredException e) {
            log.info("토큰 기한이 만료되었습니다 {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT 토큰이 잘못되었습니다. {}", e.getMessage());
            throw new JwtException("JWT 토큰이 잘못되었습니다.");
        } catch (Exception e) {
            log.error("유효하지 않은 토큰입니다. {}", e.getMessage());
            e.printStackTrace();
            throw new JwtException("JWT 예외 발생");
        }

        log.info("userIdx = {}", userIdx);
        User user = userRepository.findById(userIdx).get();

        Optional<String> refreshToken = redisRepo.getValues(user.getUsername());
        if (!refreshToken.isEmpty()) {
            redisRepo.deleteValues(user.getUsername());
        }

        return true;
    }

    /**
     * AccessToken 생성 메소드
     */
    public String createAccessToken(String username) {
        Date now = new Date();
        User user = userRepository.findByUsername(username).get();
        return JWT.create() // JWT 토큰을 생성하는 빌더 반환
                .withSubject(ACCESS_TOKEN_SUBJECT) // JWT의 Subject 지정 -> AccessToken이므로 AccessToken
                .withExpiresAt(new Date(now.getTime() + accessTokenExpirationPeriod)) // 토큰 만료 시간 설정
                .withIssuedAt(new Date(now.getTime()))
                //클레임으로는 저희는 username 하나만 사용합니다.
                //추가적으로 식별자나, 이름 등의 정보를 더 추가하셔도 됩니다.
                //추가하실 경우 .withClaim(클래임 이름, 클래임 값) 으로 설정해주시면 됩니다
                .withClaim(USERNAME_CLAIM, username)
                .withClaim(USERIDX_CLAIM, user.getUserIdx())
                .sign(Algorithm.HMAC512(secretKey)); // HMAC512 알고리즘 사용, application.yml에서 지정한 secret 키로 암호화
    }

    /**
     * RefreshToken 생성
     * RefreshToken은 Claim에 username도 넣지 않으므로 withClaim() X
     */
    public String createRefreshToken(String username) {
        Date now = new Date();
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime() + refreshTokenExpirationPeriod))
                .withIssuedAt(new Date(now.getTime()))
                .withClaim(USERNAME_CLAIM, username)
                .sign(Algorithm.HMAC512(secretKey));
    }

    /**
     * AccessToken 헤더에 실어서 보내기
     */
    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        response.setStatus(HttpServletResponse.SC_OK);

        response.setHeader(accessHeader, accessToken);
        log.info("재발급된 Access Token : {}", accessToken);
    }

    /**
     * AccessToken + RefreshToken 헤더에 실어서 보내기
     */
    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        setAccessTokenHeader(response, "Bearer " + accessToken);
        setRefreshTokenHeader(response, "Bearer " + refreshToken);
//        response.sendRedirect("/"); //"/"로 리다이렉트
        log.info("Access Token, Refresh Token 헤더 설정 완료");
    }

    /**
     * 헤더에서 RefreshToken 추출
     * 토큰 형식 : Bearer XXX에서 Bearer를 제외하고 순수 토큰만 가져오기 위해서
     * 헤더를 가져온 후 "Bearer"를 삭제(""로 replace)
     */
    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(refreshHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    /**
     * 헤더에서 AccessToken 추출
     * 토큰 형식 : Bearer XXX에서 Bearer를 제외하고 순수 토큰만 가져오기 위해서
     * 헤더를 가져온 후 "Bearer"를 삭제(""로 replace)
     */
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    /**
     * AccessToken에서 username 추출
     * 추출 전에 JWT.require()로 검증기 생성
     * verify로 AceessToken 검증 후
     * 유효하다면 getClaim()으로 username 추출
     * 유효하지 않다면 빈 Optional 객체 반환
     */
    public Optional<String> extractUsername(String accessToken) {
        try {
            // 토큰 유효성 검사하는 데에 사용할 알고리즘이 있는 JWT verifier builder 반환
            return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secretKey))
                    .build() // 반환된 빌더로 JWT verifier 생성
                    .verify(accessToken) // accessToken을 검증하고 유효하지 않다면 예외 발생
                    .getClaim(USERNAME_CLAIM) // claim(username) 가져오기
                    .asString());
        } catch (Exception e) {
            log.error("액세스 토큰이 유효하지 않습니다.");
            return Optional.empty();
        }
    }

    /**
     * AccessToken 헤더 설정
     */
    public void setAccessTokenHeader(HttpServletResponse response, String accessToken) {
        response.setHeader(accessHeader, accessToken);
    }

    /**
     * RefreshToken 헤더 설정
     */
    public void setRefreshTokenHeader(HttpServletResponse response, String refreshToken) {
        response.setHeader(refreshHeader, refreshToken);
    } //위 두개는 위에서 사용중인 메속드임

    /**
     * RefreshToken DB 저장(업데이트)
     */
    public void updateRefreshToken(String username, String refreshToken) {
        Optional<User> byUsername = userRepository.findByUsername(username);
        if (byUsername.isEmpty()) {
            new Exception("일치하는 회원이 없습니다.");
        }
        log.info("RefreshToken 업데이트");
//        User user = byUsername.get();
//        user.updateRefreshToken(refreshToken);
//        userRepository.saveAndFlush(user);
        /**
         * Redis 사용
         */
        redisRepo.setValues(username, refreshToken, Duration.ofMillis(refreshTokenExpirationPeriod));
    }

    public boolean isTokenValid(String token) {
        try {
            JWT.require(Algorithm.HMAC512(secretKey)).build().verify(token);
            return true;
        } catch (TokenExpiredException e) {
            log.error("토큰 기한이 만료되었습니다 {}", e.getMessage());
            throw new JwtException("토큰 기한이 만료되었습니다");
        } catch (IllegalArgumentException e) {
            log.error("JWT 토큰이 잘못되었습니다. {}", e.getMessage());
            throw new JwtException("JWT 토큰이 잘못되었습니다.");
        } catch (Exception e) {
            log.error("유효하지 않은 토큰입니다. {}", e.getMessage());
            throw new JwtException("JWT 예외 발생");
        }
    }

    //accessToken 남은 시간 계산
    public Long getExpiration(String accessToken) {
        Date expiration = JWT.decode(accessToken).getExpiresAt();

        Long now = new Date().getTime();

        return (expiration.getTime() - now);
    }
}
