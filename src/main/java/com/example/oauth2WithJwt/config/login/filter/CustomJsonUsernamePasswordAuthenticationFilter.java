package com.example.oauth2WithJwt.config.login.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Form Login 시 기본적으로 사용되는
 * UsernamePasswordAuthenticationFilter에서
 * AbstractAuthenticationProcessingFilter를 상속받아 구현하기 때문에,
 * 커스텀 JSON 필터에서도 AbstractAuthenticationProcessingFilter를 상속받아 구현.
 */
public class CustomJsonUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private static final String DEFAULT_LOGIN_REQUEST_URL = "/login"; //login으로 오는 요청 처리
    private static final String HTTP_METHOD = "POST"; //로그인 HTTP 메소드는 post
    private static final String CONTENT_TYPE = "application/json"; //로그인 시 요청은 JSON
    private static final String USERNAME_KEY = "username";
    private static final String PASSWORD_KEY = "password";
    private static final AntPathRequestMatcher DEFAULT_LOGIN_PATH_REQUEST_MATCHER =
            new AntPathRequestMatcher(DEFAULT_LOGIN_REQUEST_URL, HTTP_METHOD);
    // "/login" + post 로 요청시 매칭된다.

    private final ObjectMapper objectMapper;

    public CustomJsonUsernamePasswordAuthenticationFilter(ObjectMapper objectMapper) {
        super(DEFAULT_LOGIN_PATH_REQUEST_MATCHER); //매칭 처리 설정
        this.objectMapper = objectMapper;
    }

    /**
     * 인증 처리 메소드
     * 
     * usernamePasswordAuthenticationFilter와 동일하게 UsernamePasswordAuthenticationToken 사용
     * StringUtils 통해 request에서 messageBody(JSON) 반환
     * ex)
     * {
     *     "username" : "user"
     *     "password" : "2443"
     * }
     * 이렇게 요청이 오면
     * messageBody를 objectMapper.readValue() 을 통해 Map으로 변환
     * Map에서 key로 이메일, 패스워드 추출 후
     * UsernamePasswordAuthenticationToken의 파라마터 principal, credentials에 대입
     *
     * AbstractAuthenticationProcessingFilter(부모)의 getAuthenticationManager()로 AuthenticationManager 객체를 반환 받은 후
     * authenticate()의 파라미터로 UsernamePasswordAuthenticationToken 객체를 넣고 인증 처리
     * (여기서 AuthenticationManager 객체는 ProviderManager -> SecurityConfig에서 설정)
     */

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (request.getContentType() == null || !request.getContentType().equals(CONTENT_TYPE)) {
            throw new AuthenticationServiceException("Authentication Content-Type not supported : " + request.getContentType());
        }

        String messageBody = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);

        Map<String, String> usernamePasswordMap = objectMapper.readValue(messageBody, Map.class);
        //JSON 요청을 String으로 변환한 messageBody를 objectMapper.readValue를 통해 Map으로 변환하여 각각 저장

        String username = usernamePasswordMap.get(USERNAME_KEY);
        String password = usernamePasswordMap.get(PASSWORD_KEY);

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        //principal과 credentials 전달
        //AuthenticationManager가 인증 시 사용할 인증 대상 객체가

        return this.getAuthenticationManager().authenticate(authRequest);
        //이 AuthenticationManager 객체가 인증 성공/실패 처리를 함
    }
}
