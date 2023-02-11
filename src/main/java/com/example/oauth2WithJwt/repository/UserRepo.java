package com.example.oauth2WithJwt.repository;

import com.example.oauth2WithJwt.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepo extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findByRefreshToken(String refreshToken);
    Optional<User> findByEmail(String email);
}
