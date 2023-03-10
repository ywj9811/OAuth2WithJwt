package com.example.oauth2WithJwt.config.jwt.filter;

import com.example.oauth2WithJwt.config.auth.PrincipalDetails;
import com.example.oauth2WithJwt.config.jwt.service.JwtService;
import com.example.oauth2WithJwt.domain.User;
import com.example.oauth2WithJwt.dto.Response;
import com.example.oauth2WithJwt.repository.RedisRepo;
import com.example.oauth2WithJwt.repository.UserRepo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.dpop.verifiers.AccessTokenValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * JWT 인증 필터
 * 특정 url 이외의 요청이 오면 처리하도록 하는 필터
 *
 * 기본적으로 사용자는 요청시 헤더에 AccessToken만 요청
 * AccessToken 만료시 RefreshToken 요청 헤더에 Access + Refresh로 요청
 * 1. RefreshToken이 없고, AccessToken이 유효한 경우 -> 인증 성공 처리, RefreshToken을 재발급하지는 않는다.
 * 2. RefreshToken이 없고, AccessToken이 없거나 유효하지 않은 경우 -> 인증 실패 처리, 403 ERROR
 * 3. RefreshToken이 있는 경우 -> DB의 RefreshToken과 비교하여 일치하면 AccessToken 재발급, RefreshToken 재발급(RTR 방식)
 *                              인증 성공 처리는 하지 않고 실패 처리
 */
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpiration;
    private static final List<String> NOT_CHECK_URLS = Arrays.asList(new String[]{"/login", "/out", "/loginForm", "/join", "/joinForm", "/SnsLogin"});

    private final JwtService jwtService;
    private final UserRepo userRepo;
    private final RedisRepo redisRepo;

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (NOT_CHECK_URLS.contains(request.getRequestURI()) || request.getRequestURI().contains("/oauth2")) {
//        if(request.getHeader("Authorization") == null) {
            filterChain.doFilter(request, response);
            return; //처리X 요청의 경우 다음 필터로 넘기고 return을 통해 현재 필터 진행 정지
        }
        log.info("권한 검사 시작");

        // 사용자 요청 헤더에서 RefreshToken 추출
        // -> RefreshToken이 없거나 유효하지 않다면(DB에 저장된 RefreshToken과 다르다면) null을 반환
        // 사용자의 요청 헤더에 RefreshToken이 있는 경우는, AccessToken이 만료되어 요청한 경우밖에 없다.
        // 따라서, 재요청이 아닌경우 혹은 틀린 경우는 모두 null
        String refreshToken = jwtService.extractRefreshToken(request)
                .filter(jwtService::isTokenValid)
                .orElse(null);

        // 리프레시 토큰이 요청 헤더에 존재했다면, 사용자가 AccessToken이 만료되어서
        // RefreshToken까지 보낸 것이므로 리프레시 토큰이 DB의 리프레시 토큰과 일치하는지 판단 후,
        // 일치한다면 AccessToken을 재발급해준다.
        if (refreshToken != null) {
            try {
                checkRefreshTokenAndReIssueAccessToken(request, response, refreshToken);
            } catch (AccessTokenValidationException e) {
                e.printStackTrace();
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("토큰 값 비정상");
            }
            return;
        }

        // RefreshToken이 없거나 유효하지 않다면, AccessToken을 검사하고 인증을 처리하는 로직 수행
        // AccessToken이 없거나 유효하지 않다면, 인증 객체가 담기지 않은 상태로 다음 필터로 넘어가기 때문에 403 에러 발생
        // AccessToken이 유효하다면, 인증 객체가 담긴 상태로 다음 필터로 넘어가기 때문에 인증 성공
        if (refreshToken == null) {
            try {
                log.info("AccessToken 검사 진행");
                checkAccessTokenAndAuthentication(request, response, filterChain);
            } catch (AccessTokenValidationException e) {
                e.printStackTrace();
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("AccessToken 비정상");
            }
        }
    }

    /**
     *  [리프레시 토큰으로 유저 정보 찾기 & 액세스 토큰/리프레시 토큰 재발급 메소드]
     *  파라미터로 들어온 헤더에서 추출한 리프레시 토큰으로 DB에서 유저를 찾고, 해당 유저가 있다면
     *  JwtService.createAccessToken()으로 AccessToken 생성,
     *  reIssueRefreshToken()로 리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드 호출
     *  그 후 JwtService.sendAccessTokenAndRefreshToken()으로 응답 헤더에 보내기
     */
    public void checkRefreshTokenAndReIssueAccessToken(HttpServletRequest request, HttpServletResponse response, String refreshToken) throws IOException, AccessTokenValidationException {
        log.info("refreshToken 검사");
        ObjectMapper objectMapper = new ObjectMapper();

        Optional<String> username = jwtService.extractUsername(refreshToken);
        if (username.isPresent()) {
            Optional<User> byUsername = userRepo.findByUsername(username.get());
            if (byUsername.isPresent()) {
                if (!redisRepo.getValues(byUsername.get().getUsername()).isEmpty()) {
                    log.info("refreshToken 업데이트 및 AccessToken 재발급 ");
                    String reIssuedRefreshToken = reIssueRefreshToken(byUsername.get());
                    jwtService.sendAccessAndRefreshToken(response, jwtService.createAccessToken(username.get()), reIssuedRefreshToken);

                    //AccessToken 재발급 요청시 어떤 경로로 요청했는지 함께 보내줌 (헤더에 담아서)
                    String requestURI = request.getRequestURI();
                    log.info("requestURI : {}", requestURI);
                    response.setHeader("requestUrl", requestURI);
                    Response res = new Response(200,"Success");

                    PrintWriter writer = response.getWriter();
                    writer.write(objectMapper.writeValueAsString(res));
                    writer.flush();
                    return;
                }
            }
        }
        log.error("refreshToken값이 잘못되었습니다. 요청 확인 바람");
        throw new AccessTokenValidationException("RefreshToken 값 불일치");
    }

    /**
     * [리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드]
     * jwtService.createRefreshToken()으로 리프레시 토큰 재발급 후
     */
    private String reIssueRefreshToken(User user) {
        String reIssuedRefreshToken = jwtService.createRefreshToken(user.getUsername());
//        user.updateRefreshToken(reIssuedRefreshToken);
//        userRepo.saveAndFlush(user);
        /**
         * Redis 사용 수정
         */
        redisRepo.setValues(user.getUsername(), reIssuedRefreshToken, Duration.ofMillis(refreshTokenExpiration));
        /////////////////////////////
        return reIssuedRefreshToken;
    }

    /**
     * [액세스 토큰 체크 & 인증 처리 메소드]
     * request에서 extractAccessToken()으로 액세스 토큰 추출 후, isTokenValid()로 유효한 토큰인지 검증
     * 유효한 토큰이면, 액세스 토큰에서 extractUsername을 통해 username을 추출한 후 findByUseranme()로 해당 아이디를 사용하는 유저 객체 반환
     * 그 유저 객체를 saveAuthentication()으로 인증 처리하여
     * 인증 허가 처리된 객체를 SecurityContextHolder에 담기
     * 그 후 다음 인증 필터로 진행
     */
    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException, AccessTokenValidationException {
        log.info("checkAccessTokenAndAuthentication() 호출");
        Optional<String> accessToken = jwtService.extractAccessToken(request)
                .filter(jwtService::isTokenValid);
        if (accessToken.isPresent()) {
            log.info("----------------------------------------------------");
            log.info("AccessToken.value = {}", redisRepo.getValues(accessToken.get()));
            log.info("----------------------------------------------------");
            if (!redisRepo.getValues(accessToken.get()).isPresent()) {
                Optional<String> username = jwtService.extractUsername(accessToken.get());
                if (username.isPresent()) {
                    Optional<User> user = userRepo.findByUsername(username.get());
                    if (user.isPresent()) {
                        saveAuthentication(user.get());
                        filterChain.doFilter(request, response);
                        return;
                    }
                }
                log.error("username이 없음");
            }
            log.error("블랙리스트 등록 accessToken 접근");
        }
        log.error("AccessToken 비정상");
        log.info("RequestUri = {}", request.getRequestURI());
        throw new AccessTokenValidationException("AccessToken 비정상");
    }

    /**
     * [인증 허가 메소드]
     * 파라미터의 유저 : 우리가 만든 회원 객체 / 빌더의 유저 : PrincipalDetails의 User 객체
     *
     * new UsernamePasswordAuthenticationToken()로 인증 객체인 Authentication 객체 생성
     * UsernamePasswordAuthenticationToken의 파라미터
     * 1. 위에서 만든 UserDetailsUser 객체 (유저 정보)
     * 2. credential(보통 비밀번호로, 인증 시에는 보통 null로 제거)
     * 3. Collection < ? extends GrantedAuthority>로,
     * PrincipalDetails의 User 객체 안에 Set<GrantedAuthority> authorities이 있어서 getter로 호출한 후에,
     * new NullAuthoritiesMapper()로 GrantedAuthoritiesMapper 객체를 생성하고 mapAuthorities()에 담기
     *
     * SecurityContextHolder.getContext()로 SecurityContext를 꺼낸 후,
     * setAuthentication()을 이용하여 위에서 만든 Authentication 객체에 대한 인증 허가 처리
    */
    public void saveAuthentication(User user) {
        PrincipalDetails principalDetails = new PrincipalDetails(user);

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(principalDetails, null,
                        authoritiesMapper.mapAuthorities(principalDetails.getAuthorities()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
