package com.example.oauth2WithJwt.dto;

import com.example.oauth2WithJwt.domain.User;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class UserDto {
    String username;
    String password;
    String email;

    public User dtoToDomain() {
        return User.builder()
                .username(username)
                .email(email)
                .password(password)
                .build();
    }
}
