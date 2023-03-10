package com.example.oauth2WithJwt.config;

import com.example.oauth2WithJwt.config.auth.PrincipalDetailsService;
import com.example.oauth2WithJwt.config.jwt.filter.JwtAuthenticationProcessingFilter;
import com.example.oauth2WithJwt.config.jwt.service.JwtService;
import com.example.oauth2WithJwt.config.login.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import com.example.oauth2WithJwt.config.login.handler.LoginFailureHandler;
import com.example.oauth2WithJwt.config.login.handler.LoginSuccessHandler;
import com.example.oauth2WithJwt.config.oauth2.handler.OAuth2LoginFailureHandler;
import com.example.oauth2WithJwt.config.oauth2.handler.OAuth2LoginSuccessHandler;
import com.example.oauth2WithJwt.config.oauth2.service.PrincipalOauth2UserService;
import com.example.oauth2WithJwt.repository.RedisRepo;
import com.example.oauth2WithJwt.repository.UserRepo;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserRepo userRepo;
    private final RedisTemplate<String, String> redisTemplate;
    private final RedisRepo redisRepo;
    private final PrincipalDetailsService principalDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final PrincipalOauth2UserService principalOauth2UserService;
    private final CorsConfig corsConfig;
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    /**
     * AuthenticationManager ?????? ??? ??????
     * PasswordEncoder??? ???????????? AuthenticationProvider ?????? (PasswordEncoder??? ????????? ????????? PasswordEncoder ??????)
     * FormLogin(?????? ????????? ???????????? ?????????)??? ???????????? DaoAuthenticationProvider ??????
     * UserDetailsService??? ????????? PrincipalDetailsService ??????
     * ??????, FormLogin??? ???????????? AuthenticationManager?????? ???????????? ProviderManager ??????(return ProviderManager)
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(bCryptPasswordEncoder);
        provider.setUserDetailsService(principalDetailsService);
        return new ProviderManager(provider);
    }

    /**
     * ????????? ?????? ??? ???????????? LoginSuccessJWTProviderHandler ??? ??????
     */
    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, userRepo, redisRepo);
    }

    /**
     * ????????? ?????? ??? ???????????? LoginFailureHandler ??? ??????
     */
    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

    /**
     * CustomJsonUsernamePasswordAuthenticationFilter ??? ??????
     * ????????? ????????? ???????????? ?????? ?????? ????????? ????????? Bean?????? ??????
     * setAuthenticationManager(authenticationManager())??? ????????? ????????? AuthenticationManager(ProviderManager) ??????
     * ????????? ?????? ??? ????????? handler, ?????? ??? ????????? handler??? ????????? ????????? handler ??????
     */

    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter() {
        CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter
                = new CustomJsonUsernamePasswordAuthenticationFilter(objectMapper);
        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationManager(authenticationManager());
        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return customJsonUsernamePasswordAuthenticationFilter;
    }

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() {
        JwtAuthenticationProcessingFilter jwtAuthenticationFilter = new JwtAuthenticationProcessingFilter(jwtService, userRepo, redisRepo);
        return jwtAuthenticationFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .formLogin().disable() //FormLogin ?????? ?????? (?????? ????????? ?????? ??????(json)
                .httpBasic().disable();// httpBasic ?????? ?????? (JWT ????????? ????????? ????????? ????????? ?????? ??????)

        http
                //?????? ?????? ???????????? ??????
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                //url??? ?????? ??????
                .and()
                .authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()

                //?????? ????????? ??????
                .and()
                .oauth2Login()
                .successHandler(oAuth2LoginSuccessHandler)
                .failureHandler(oAuth2LoginFailureHandler)
                //????????? oauth2/authorization/????????? ?????? ??????
                //???, ???????????? ????????? ????????? ???????????? ?????????
                .userInfoEndpoint().userService(principalOauth2UserService); //customUserService ??????

        http
                .addFilter(corsConfig.corsFilter())
                .addFilterAfter(customJsonUsernamePasswordAuthenticationFilter(), LogoutFilter.class)
                .addFilterBefore(jwtAuthenticationProcessingFilter(), CustomJsonUsernamePasswordAuthenticationFilter.class);
    }
}
