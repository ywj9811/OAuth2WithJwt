package com.example.oauth2WithJwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);
        //이 부분은 내 서버가 응답할 때 json을 자바스크립트에서 처리할 수 있게 할지를 설정하는 것임 -> 자바스크립트 요청을 받으려면 true

        config.addAllowedOrigin("*");
        //모든 ip에 응답을 허용
        config.addAllowedHeader("*");
        //모든 header에 응답을 허용
        config.addAllowedMethod("*");
        //모든 Post, get, Put과 같은 요청을 허용
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}